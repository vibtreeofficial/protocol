// Copyright 2023 Vibtree, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ingress

import (
	"time"

	"github.com/vibtreeofficial/protocol/auth"
	"github.com/vibtreeofficial/protocol/media-router"
)

func BuildIngressToken(apiKey, secret, roomName, participantIdentity, participantName, participantMetadata, ingressID string) (string, error) {
	f := false
	t := true
	grant := &auth.VideoGrant{
		RoomJoin:             true,
		Room:                 roomName,
		CanSubscribe:         &f,
		CanPublish:           &t,
		CanUpdateOwnMetadata: &t,
	}

	at := auth.NewAccessToken(apiKey, secret).
		SetVideoGrant(grant).
		SetIdentity(participantIdentity).
		SetName(participantName).
		SetKind(media_router.ParticipantInfo_INGRESS).
		SetValidFor(24 * time.Hour).
		SetMetadata(participantMetadata).
		SetAttributes(map[string]string{
			media_router.AttrIngressID: ingressID,
		})

	return at.ToJWT()
}
