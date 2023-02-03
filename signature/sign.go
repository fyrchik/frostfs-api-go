package signature

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/TrueCloudLab/frostfs-api-go/v2/accounting"
	"github.com/TrueCloudLab/frostfs-api-go/v2/container"
	"github.com/TrueCloudLab/frostfs-api-go/v2/netmap"
	"github.com/TrueCloudLab/frostfs-api-go/v2/object"
	"github.com/TrueCloudLab/frostfs-api-go/v2/reputation"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/signature"
)

type Request interface {
	GetMetaHeader() *session.RequestMetaHeader
	GetVerificationHeader() *session.RequestVerificationHeader
	SetVerificationHeader(*session.RequestVerificationHeader)
}

type MessageBody interface {
	StableMarshal([]byte) []byte
	StableSize() int
}

type Response interface {
	GetMetaHeader() *session.ResponseMetaHeader
	GetVerificationHeader() *session.ResponseVerificationHeader
	SetVerificationHeader(*session.ResponseVerificationHeader)
}

func SignRequest(s *signature.Signer, header Request, body MessageBody) error {
	verifyHdr := new(session.RequestVerificationHeader)

	verifyOrigin := header.GetVerificationHeader()
	if verifyOrigin == nil {
		sig, err := s.SignStable(body)
		if err != nil {
			return fmt.Errorf("could not sign body: %w", err)
		}
		verifyHdr.SetBodySignature(sig)
	}

	sig, err := s.SignStable(header.GetMetaHeader())
	if err != nil {
		return fmt.Errorf("could not sign meta header: %w", err)
	}
	verifyHdr.SetMetaSignature(sig)

	sig, err = s.SignStable(verifyOrigin)
	if err != nil {
		return fmt.Errorf("could not sign origin of verification header: %w", err)
	}
	verifyHdr.SetOriginSignature(sig)

	// wrap origin verification header
	verifyHdr.SetOrigin(verifyOrigin)
	header.SetVerificationHeader(verifyHdr)
	return nil
}

func SignResponse(key *ecdsa.PrivateKey, header Response, body MessageBody) error {
	s, err := signature.NewSigner(key, nil)
	if err != nil {
		return err
	}

	verifyHdr := new(session.ResponseVerificationHeader)

	verifyOrigin := header.GetVerificationHeader()
	if verifyOrigin == nil {
		sig, err := s.SignStable(body)
		if err != nil {
			return fmt.Errorf("could not sign body: %w", err)
		}
		verifyHdr.SetBodySignature(sig)
	}

	sig, err := s.SignStable(header.GetMetaHeader())
	if err != nil {
		return fmt.Errorf("could not sign meta header: %w", err)
	}
	verifyHdr.SetMetaSignature(sig)

	sig, err = s.SignStable(verifyOrigin)
	if err != nil {
		return fmt.Errorf("could not sign origin of verification header: %w", err)
	}
	verifyHdr.SetOriginSignature(sig)

	// wrap origin verification header
	verifyHdr.SetOrigin(verifyOrigin)
	header.SetVerificationHeader(verifyHdr)
	return nil
}

// SignServiceMessage signs FrostFS API service request or response with a private key.
// Deprecated: use SignRequest or SignResponse instead.
func SignServiceMessage(key *ecdsa.PrivateKey, msg interface{}) error {
	switch v := msg.(type) {
	case nil:
		return nil
	case Request:
		return SignRequest(key, v, serviceMessageBody(v))
	case Response:
		return SignResponse(key, v, serviceMessageBody(v))
	default:
		panic(fmt.Sprintf("unsupported session message %T", v))
	}
}

func serviceMessageBody(req interface{}) MessageBody {
	switch v := req.(type) {
	default:
		panic(fmt.Sprintf("unsupported session message %T", req))

		/* Accounting */
	case *accounting.BalanceRequest:
		return v.GetBody()
	case *accounting.BalanceResponse:
		return v.GetBody()

		/* Session */
	case *session.CreateRequest:
		return v.GetBody()
	case *session.CreateResponse:
		return v.GetBody()

		/* Container */
	case *container.PutRequest:
		return v.GetBody()
	case *container.PutResponse:
		return v.GetBody()
	case *container.DeleteRequest:
		return v.GetBody()
	case *container.DeleteResponse:
		return v.GetBody()
	case *container.GetRequest:
		return v.GetBody()
	case *container.GetResponse:
		return v.GetBody()
	case *container.ListRequest:
		return v.GetBody()
	case *container.ListResponse:
		return v.GetBody()
	case *container.SetExtendedACLRequest:
		return v.GetBody()
	case *container.SetExtendedACLResponse:
		return v.GetBody()
	case *container.GetExtendedACLRequest:
		return v.GetBody()
	case *container.GetExtendedACLResponse:
		return v.GetBody()
	case *container.AnnounceUsedSpaceRequest:
		return v.GetBody()
	case *container.AnnounceUsedSpaceResponse:
		return v.GetBody()

		/* Object */
	case *object.PutRequest:
		return v.GetBody()
	case *object.PutResponse:
		return v.GetBody()
	case *object.GetRequest:
		return v.GetBody()
	case *object.GetResponse:
		return v.GetBody()
	case *object.HeadRequest:
		return v.GetBody()
	case *object.HeadResponse:
		return v.GetBody()
	case *object.SearchRequest:
		return v.GetBody()
	case *object.SearchResponse:
		return v.GetBody()
	case *object.DeleteRequest:
		return v.GetBody()
	case *object.DeleteResponse:
		return v.GetBody()
	case *object.GetRangeRequest:
		return v.GetBody()
	case *object.GetRangeResponse:
		return v.GetBody()
	case *object.GetRangeHashRequest:
		return v.GetBody()
	case *object.GetRangeHashResponse:
		return v.GetBody()

		/* Netmap */
	case *netmap.LocalNodeInfoRequest:
		return v.GetBody()
	case *netmap.LocalNodeInfoResponse:
		return v.GetBody()
	case *netmap.NetworkInfoRequest:
		return v.GetBody()
	case *netmap.NetworkInfoResponse:
		return v.GetBody()
	case *netmap.SnapshotRequest:
		return v.GetBody()
	case *netmap.SnapshotResponse:
		return v.GetBody()

		/* Reputation */
	case *reputation.AnnounceLocalTrustRequest:
		return v.GetBody()
	case *reputation.AnnounceLocalTrustResponse:
		return v.GetBody()
	case *reputation.AnnounceIntermediateResultRequest:
		return v.GetBody()
	case *reputation.AnnounceIntermediateResultResponse:
		return v.GetBody()
	}
}
