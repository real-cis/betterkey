package web

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/go-tdx-guest/proto/tdx"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

type PolicyService interface {
	Upsert(request PolicyUpdateRequest) error
	Delete(id string) error
	Verify(id string, quote *tdx.QuoteV4) (bool, error)
}

type DefaultPolicyService struct {
	store common.BaseKeyStore
}

func NewPolicyService(store common.BaseKeyStore) PolicyService {
	return &DefaultPolicyService{
		store: store,
	}
}

func (p *DefaultPolicyService) Upsert(policyRequest PolicyUpdateRequest) error {
	jsonData, err := json.Marshal(policyRequest)
	if err != nil {
		return err
	}

	return p.store.Write(policyRequest.Id, jsonData)
}

func (p *DefaultPolicyService) Delete(id string) error {
	exists, err := p.store.Exists(id)
	if err != nil {
		return err
	} else if exists > 0 {
		return p.store.Delete(id)
	}
	return nil
}

func (p *DefaultPolicyService) Verify(id string, quote *tdx.QuoteV4) (bool, error) {
	jsonData, err := p.store.Read(id)
	if p.store.HasNil(err) {
		// TODO no policy set
		slog.Info("no policy set for id, default allow", "id", id)
		return true, nil
	}
	policyData := PolicyUpdateRequest{}
	if err = json.Unmarshal(jsonData, &policyData); err != nil {
		return false, NewError("Failed to fetch payload from policy store", http.StatusInternalServerError)
	}
	// verify integrity with a matching id
	if policyData.Id != id {
		slog.Warn("id mismatch for policy entry", "expected", policyData.Id, "stored", id)
		return false, NewError("id mismatch", http.StatusUnauthorized)
	}
	slog.Info("verifying policy", "mrtd", policyData.Mrtd, "quote_mrtd", hex.EncodeToString(quote.TdQuoteBody.MrTd))
	return policyData.Mrtd == hex.EncodeToString(quote.TdQuoteBody.MrTd), nil
}
