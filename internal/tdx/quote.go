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
	MatchRTMR(quoteV4 *tdx.QuoteV4, rtmr0 []byte, rtmr1 []byte, rtmr2 []byte) error
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

func (q *TdxQuoteVerifier) MatchRTMR(quoteV4 *tdx.QuoteV4, rtmr0 []byte, rtmr1 []byte, rtmr2 []byte) error {
	slog.Info("Matching RTMRs", "quoteRTMR0", fmt.Sprintf("%x", quoteV4.TdQuoteBody.Rtmrs[0]), "expectedRTMR0", fmt.Sprintf("%x", rtmr0))
	if !bytes.Equal(quoteV4.TdQuoteBody.Rtmrs[0], rtmr0) {
		return fmt.Errorf("RTMR0 does not match")
	}
	slog.Info("Matching RTMRs", "quoteRTMR1", fmt.Sprintf("%x", quoteV4.TdQuoteBody.Rtmrs[1]), "expectedRTMR1", fmt.Sprintf("%x", rtmr1))

	if !bytes.Equal(quoteV4.TdQuoteBody.Rtmrs[1], rtmr1) {
		return fmt.Errorf("RTMR1 does not match")
	}
	slog.Info("Matching RTMRs", "quoteRTMR2", fmt.Sprintf("%x", quoteV4.TdQuoteBody.Rtmrs[2]), "expectedRTMR2", fmt.Sprintf("%x", rtmr2))

	if !bytes.Equal(quoteV4.TdQuoteBody.Rtmrs[2], rtmr2) {
		return fmt.Errorf("RTMR2 does not match")
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
