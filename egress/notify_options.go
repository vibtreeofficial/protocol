// Copyright 2025 Vibtree, Inc.
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

package egress

import (
	"github.com/vibtreeofficial/protocol/media-router"
	"github.com/vibtreeofficial/protocol/webhook"
)

func GetEgressNotifyOptions(egressInfo *media_router.EgressInfo) []webhook.NotifyOption {
	if egressInfo == nil {
		return nil
	}

	if egressInfo.Request == nil {
		return nil
	}

	var whs []*media_router.WebhookConfig

	switch req := egressInfo.Request.(type) {
	case *media_router.EgressInfo_RoomComposite:
		if req.RoomComposite != nil {
			whs = req.RoomComposite.Webhooks
		}
	case *media_router.EgressInfo_Web:
		if req.Web != nil {
			whs = req.Web.Webhooks
		}
	case *media_router.EgressInfo_Participant:
		if req.Participant != nil {
			whs = req.Participant.Webhooks
		}
	case *media_router.EgressInfo_TrackComposite:
		if req.TrackComposite != nil {
			whs = req.TrackComposite.Webhooks
		}
	case *media_router.EgressInfo_Track:
		if req.Track != nil {
			whs = req.Track.Webhooks
		}
	}

	if len(whs) > 0 {
		return []webhook.NotifyOption{webhook.WithExtraWebhooks(whs)}
	}

	return nil
}
