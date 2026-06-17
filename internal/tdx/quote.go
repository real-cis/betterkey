package tdx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

type TdxQuote struct {
	raw    []byte
	parsed *tdx.QuoteV4
}

func NewTdxQuote(rawQuote []byte) (*TdxQuote, error) {
	if len(rawQuote) == 0 {
		return nil, fmt.Errorf("empty quote provided")
	}

	quotev4, err := abi.QuoteToProto(rawQuote)
	if err != nil {
		return nil, fmt.Errorf("parsing TDX quote: %w", err)
	}

	parsed, ok := quotev4.(*tdx.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("failed to cast parsed quote to *tdx.QuoteV4")
	}

	return &TdxQuote{
		raw:    rawQuote,
		parsed: parsed,
	}, nil
}

func (q *TdxQuote) Parsed() *tdx.QuoteV4 {
	return q.parsed
}

func (q *TdxQuote) Raw() []byte {
	return q.raw
}

func (q *TdxQuote) Verify() error {
	opt := verify.DefaultOptions()
	opt.GetCollateral = true
	opt.CheckRevocations = true
	return verify.RawTdxQuote(q.raw, opt)
}

func (q *TdxQuote) VerifyReportData(expectedReportData []byte) error {
	if !bytes.Equal(q.parsed.TdQuoteBody.ReportData, expectedReportData) {
		return fmt.Errorf("report data does not match: expected %x, got %x",
			expectedReportData, q.parsed.TdQuoteBody.ReportData)
	}
	return nil
}

func (q *TdxQuote) VerifyRTMRs(rtmr0, rtmr1, rtmr2 []byte) error {
	if err := q.VerifyRTMR(0, rtmr0); err != nil {
		return err
	}
	if err := q.VerifyRTMR(1, rtmr1); err != nil {
		return err
	}
	if err := q.VerifyRTMR(2, rtmr2); err != nil {
		return err
	}
	return nil
}

func (q *TdxQuote) VerifyRTMR(index int, expected []byte) error {
	if index < 0 || index >= len(q.parsed.TdQuoteBody.Rtmrs) {
		return fmt.Errorf("invalid RTMR index: %d", index)
	}

	actual := q.parsed.TdQuoteBody.Rtmrs[index]
	slog.Info("Matching RTMRs", "index", index, "quoteRTMR",
		fmt.Sprintf("%x", actual), "expectedRTMR", fmt.Sprintf("%x", expected))

	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("RTMR%d does not match: expected %x, got %x",
			index, expected, actual)
	}
	return nil
}

func (q *TdxQuote) GetMrTd() []byte {
	return q.parsed.TdQuoteBody.MrTd
}

func (q *TdxQuote) GetRTMR(index int) ([]byte, error) {
	if index < 0 || index >= len(q.parsed.TdQuoteBody.Rtmrs) {
		return nil, fmt.Errorf("invalid RTMR index: %d", index)
	}
	return q.parsed.TdQuoteBody.Rtmrs[index], nil
}

// quote header for exporting
type QuoteHeader struct {
	Version            uint32 `json:"version"`
	AttestationKeyType uint32 `json:"attestationKeyType"`
	TeeType            uint32 `json:"teeType"`
	QeSvn              []byte `json:"qeSvn"`
	PceSvn             []byte `json:"pceSvn"`
	QeVendorId         []byte `json:"qeVendorId"`
	UserData           []byte `json:"userData"`
}

// quote body for exporting
type QuoteBody struct {
	TeeTcbSvn      []byte   `json:"teeTcbSvn"`
	MrSeam         []byte   `json:"mrSeam"`
	MrSignerSeam   []byte   `json:"mrSignerSeam"`
	SeamAttributes []byte   `json:"seamAttributes"`
	TdAttributes   []byte   `json:"tdAttributes"`
	Xfam           []byte   `json:"xfam"`
	MrTd           []byte   `json:"mrTd"`
	MrConfigId     []byte   `json:"mrConfigId"`
	MrOwner        []byte   `json:"mrOwner"`
	MrOwnerConfig  []byte   `json:"mrOwnerConfig"`
	Rtmrs          [][]byte `json:"rtmrs"`
	ReportData     []byte   `json:"reportData"`
}

// JSON-serializable view of a parsed TDX quote.
type QuoteSummary struct {
	Header QuoteHeader `json:"header"`
	Body   QuoteBody   `json:"body"`
}

// returns a JSON-serializable summary of the quote's header and body.
func (q *TdxQuote) Summary() *QuoteSummary {
	h := q.parsed.GetHeader()
	b := q.parsed.GetTdQuoteBody()

	return &QuoteSummary{
		Header: QuoteHeader{
			Version:            h.GetVersion(),
			AttestationKeyType: h.GetAttestationKeyType(),
			TeeType:            h.GetTeeType(),
			QeSvn:              h.GetQeSvn(),
			PceSvn:             h.GetPceSvn(),
			QeVendorId:         h.GetQeVendorId(),
			UserData:           h.GetUserData(),
		},
		Body: QuoteBody{
			TeeTcbSvn:      b.GetTeeTcbSvn(),
			MrSeam:         b.GetMrSeam(),
			MrSignerSeam:   b.GetMrSignerSeam(),
			SeamAttributes: b.GetSeamAttributes(),
			TdAttributes:   b.GetTdAttributes(),
			Xfam:           b.GetXfam(),
			MrTd:           b.GetMrTd(),
			MrConfigId:     b.GetMrConfigId(),
			MrOwner:        b.GetMrOwner(),
			MrOwnerConfig:  b.GetMrOwnerConfig(),
			Rtmrs:          b.GetRtmrs(),
			ReportData:     b.GetReportData(),
		},
	}
}

// returns the summary as JSON; best effort, empty on error.
func (s *QuoteSummary) JSON() string {
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(b)
}

// VerifyChain performs a complete verification chain
func (q *TdxQuote) VerifyChain(reportData []byte, rtmr0, rtmr1, rtmr2 []byte) error {
	if err := q.Verify(); err != nil {
		return fmt.Errorf("quote cryptographic verification failed: %w", err)
	}

	if err := q.VerifyReportData(reportData); err != nil {
		return fmt.Errorf("report data verification failed: %w", err)
	}

	if err := q.VerifyRTMRs(rtmr0, rtmr1, rtmr2); err != nil {
		return fmt.Errorf("RTMR verification failed: %w", err)
	}

	return nil
}
