package agent

import (
	"time"

	"github.com/vibtreeofficial/protocol/auth"
	"github.com/vibtreeofficial/protocol/media-router"
)

func BuildAgentToken(
	apiKey, secret, roomName, participantIdentity, participantName, participantMetadata string,
	participantAttributes map[string]string,
	permissions *media_router.ParticipantPermission,
) (string, error) {
	grant := &auth.VideoGrant{
		RoomJoin:             true,
		Agent:                true,
		Room:                 roomName,
		CanSubscribe:         &permissions.CanSubscribe,
		CanPublish:           &permissions.CanPublish,
		CanPublishData:       &permissions.CanPublishData,
		Hidden:               permissions.Hidden,
		CanUpdateOwnMetadata: &permissions.CanUpdateMetadata,
		CanSubscribeMetrics:  &permissions.CanSubscribeMetrics,
	}

	at := auth.NewAccessToken(apiKey, secret).
		SetVideoGrant(grant).
		SetIdentity(participantIdentity).
		SetName(participantName).
		SetKind(media_router.ParticipantInfo_AGENT).
		SetValidFor(1 * time.Hour).
		SetMetadata(participantMetadata).
		SetAttributes(participantAttributes)

	return at.ToJWT()
}
