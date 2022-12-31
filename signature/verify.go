package signature

import (
	"errors"
	"fmt"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/signature"
)

func VerifyRequest(r Request, body MessageBody) error {
	size := body.StableSize()

	meta := r.GetMetaHeader()
	if sz := meta.StableSize(); sz > size {
		size = sz
	}

	verify := r.GetVerificationHeader()
	if sz := verify.StableSize(); sz > size {
		size = sz
	}

	buf := make([]byte, 0, size)
	return verifyMatryoshkaLevelRequest(body, meta, verify, buf)
}

func VerifyResponse(r Response, body MessageBody) error {
	size := body.StableSize()

	meta := r.GetMetaHeader()
	if sz := meta.StableSize(); sz > size {
		size = sz
	}

	verify := r.GetVerificationHeader()
	if sz := verify.StableSize(); sz > size {
		size = sz
	}

	buf := make([]byte, 0, size)
	return verifyMatryoshkaLevelResponse(body, meta, verify, buf)
}

// VerifyServiceMessage signs FrostFS API service request or response with a private key.
// Deprecated: use VerifyRequest or VerifyResponse instead.
func VerifyServiceMessage(msg interface{}) error {
	switch v := msg.(type) {
	case nil:
		return nil
	case Request:
		return VerifyRequest(v, serviceMessageBody(v))
	case Response:
		return VerifyResponse(v, serviceMessageBody(v))
	default:
		panic(fmt.Sprintf("unsupported session message %T", v))
	}
}

func verifyMatryoshkaLevelRequest(body MessageBody, meta *session.RequestMetaHeader, verify *session.RequestVerificationHeader, buf []byte) error {
	if err := verifyServiceMessagePart(meta, verify.GetMetaSignature, buf); err != nil {
		return fmt.Errorf("could not verify meta header: %w", err)
	}

	origin := verify.GetOrigin()
	if err := verifyServiceMessagePart(origin, verify.GetOriginSignature, buf); err != nil {
		return fmt.Errorf("could not verify origin of verification header: %w", err)
	}

	if origin == nil {
		if err := verifyServiceMessagePart(body, verify.GetBodySignature, buf); err != nil {
			return fmt.Errorf("could not verify body: %w", err)
		}

		return nil
	}

	if verify.GetBodySignature() != nil {
		return errors.New("body signature at the matryoshka upper level")
	}

	return verifyMatryoshkaLevelRequest(body, meta.GetOrigin(), origin, buf)
}

func verifyMatryoshkaLevelResponse(body MessageBody, meta *session.ResponseMetaHeader, verify *session.ResponseVerificationHeader, buf []byte) error {
	if err := verifyServiceMessagePart(meta, verify.GetMetaSignature, buf); err != nil {
		return fmt.Errorf("could not verify meta header: %w", err)
	}

	origin := verify.GetOrigin()
	if err := verifyServiceMessagePart(origin, verify.GetOriginSignature, buf); err != nil {
		return fmt.Errorf("could not verify origin of verification header: %w", err)
	}

	if origin == nil {
		if err := verifyServiceMessagePart(body, verify.GetBodySignature, buf); err != nil {
			return fmt.Errorf("could not verify body: %w", err)
		}

		return nil
	}

	if verify.GetBodySignature() != nil {
		return errors.New("body signature at the matryoshka upper level")
	}

	return verifyMatryoshkaLevelResponse(body, meta.GetOrigin(), origin, buf)
}

func verifyServiceMessagePart(part MessageBody, sigRdr func() *refs.Signature, buf []byte) error {
	return signature.VerifyDataWithSource(
		&sigWrapper{part},
		sigRdr,
		signature.WithBuffer(buf),
	)
}
