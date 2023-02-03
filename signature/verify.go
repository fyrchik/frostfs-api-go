package signature

import (
	"errors"
	"fmt"

	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/signature"
)

func VerifyRequest(v *signature.Verifier, r Request, body MessageBody) error {
	return verifyMatryoshkaLevelRequest(v, body, r.GetMetaHeader(), r.GetVerificationHeader())
}

func VerifyResponse(v *signature.Verifier, r Response, body MessageBody) error {
	return verifyMatryoshkaLevelResponse(v, body, r.GetMetaHeader(), r.GetVerificationHeader())
}

// VerifyServiceMessage signs FrostFS API service request or response with a private key.
// Deprecated: use VerifyRequest or VerifyResponse instead.
func VerifyServiceMessage(msg interface{}) error {
	switch v := msg.(type) {
	case nil:
		return nil
	case Request:
		return VerifyRequest(signature.NewVerifier(nil), v, serviceMessageBody(v))
	case Response:
		return VerifyResponse(signature.NewVerifier(nil), v, serviceMessageBody(v))
	default:
		panic(fmt.Sprintf("unsupported session message %T", v))
	}
}

func verifyMatryoshkaLevelRequest(v *signature.Verifier, body MessageBody, meta *session.RequestMetaHeader, verify *session.RequestVerificationHeader) error {
	if err := v.VerifyStable(meta, verify.GetMetaSignature()); err != nil {
		return fmt.Errorf("could not verify meta header: %w", err)
	}

	origin := verify.GetOrigin()
	if err := v.VerifyStable(origin, verify.GetOriginSignature()); err != nil {
		return fmt.Errorf("could not verify origin of verification header: %w", err)
	}

	if origin == nil {
		if err := v.VerifyStable(body, verify.GetBodySignature()); err != nil {
			return fmt.Errorf("could not verify body: %w", err)
		}

		return nil
	}

	if verify.GetBodySignature() != nil {
		return errors.New("body signature at the matryoshka upper level")
	}

	return verifyMatryoshkaLevelRequest(v, body, meta.GetOrigin(), origin)
}

func verifyMatryoshkaLevelResponse(v *signature.Verifier, body MessageBody, meta *session.ResponseMetaHeader, verify *session.ResponseVerificationHeader) error {
	if err := v.VerifyStable(meta, verify.GetMetaSignature()); err != nil {
		return fmt.Errorf("could not verify meta header: %w", err)
	}

	origin := verify.GetOrigin()
	if err := v.VerifyStable(origin, verify.GetOriginSignature()); err != nil {
		return fmt.Errorf("could not verify origin of verification header: %w", err)
	}

	if origin == nil {
		if err := v.VerifyStable(body, verify.GetBodySignature()); err != nil {
			return fmt.Errorf("could not verify body: %w", err)
		}

		return nil
	}

	if verify.GetBodySignature() != nil {
		return errors.New("body signature at the matryoshka upper level")
	}

	return verifyMatryoshkaLevelResponse(v, body, meta.GetOrigin(), origin)
}
