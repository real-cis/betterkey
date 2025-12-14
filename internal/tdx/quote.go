package tdx

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

type QuoteVerifier interface {
	Parse(rawQuote []byte) (*tdx.QuoteV4, error)
	Verify(quote []byte) (*tdx.QuoteV4, error)
	MatchReportData(quote []byte, expectedReportData []byte) error
}

type TdxQuoteVerifier struct{}

func NewTdxQuoteVerifier() QuoteVerifier {
	return &TdxQuoteVerifier{}
}

func (v *TdxQuoteVerifier) Parse(rawQuote []byte) (*tdx.QuoteV4, error) {
	quotev4, err := abi.QuoteToProto(rawQuote)
	if err != nil {
		return &tdx.QuoteV4{}, fmt.Errorf("parsing TDX quote: %w", err)
	}
	parsedBytes, ok := quotev4.(*tdx.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("failed to cast parsed quote to *tdx.QuoteV4")
	}
	return parsedBytes, nil
}

func (v *TdxQuoteVerifier) Verify(rawQuote []byte) (*tdx.QuoteV4, error) {
	quote, err := v.Parse(rawQuote)
	if err != nil {
		return nil, err
	}
	opt := verify.DefaultOptions()
	opt.GetCollateral = true
	opt.CheckRevocations = true
	return quote, verify.RawTdxQuote(rawQuote, opt)
}

func (v *TdxQuoteVerifier) MatchReportData(rawQuote []byte, expectedReportData []byte) error {
	quote, err := v.Parse(rawQuote)
	if err != nil {
		return err
	}
	if !bytes.Equal(quote.TdQuoteBody.ReportData, expectedReportData) {
		return fmt.Errorf("report data does not match")
	}
	return nil
}

type DevTdxQuoteVerifier struct {
	*TdxQuoteVerifier
}

func NewDevTdxQuoteVerifier() QuoteVerifier {
	return &DevTdxQuoteVerifier{
		TdxQuoteVerifier: &TdxQuoteVerifier{},
	}
}

func (m *DevTdxQuoteVerifier) MatchReportData(rawQuote []byte, expectedReportData []byte) error {
	_, err := m.Parse(rawQuote)
	slog.Info("Dev mode: skip matching report data")
	return err
}
