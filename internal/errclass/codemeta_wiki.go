// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package errclass

import (
	"github.com/larksuite/cli/errs"
	"github.com/larksuite/cli/internal/recovery"
)

const wikiPermissionDeniedCode = 131006

const wikiPermissionDeniedHint = "The current user or app/bot identity lacks access to the target wiki space or node. This is resource access, not app scope authorization. Do not retry the same request, reauthorize, or switch identity as trial and error; ask the resource owner or wiki administrator to grant read access, or use an accessible resource."

// wikiCodeMeta holds wiki-service Lark code -> CodeMeta mappings observed from
// wiki shortcut failure telemetry. Keep these to wiki-wide meanings only; add
// command-specific recovery guidance at the shortcut layer.
var wikiCodeMeta = map[int]CodeMeta{
	131002:                   {Category: errs.CategoryAPI, Subtype: errs.SubtypeInvalidParameters},          // param err: space_id is not int / invalid page_token
	131005:                   {Category: errs.CategoryAPI, Subtype: errs.SubtypeNotFound},                   // wiki node / space not found
	wikiPermissionDeniedCode: {Category: errs.CategoryAuthorization, Subtype: errs.SubtypePermissionDenied}, // wiki space/node read permission denied
}

func init() { mergeCodeMeta(wikiCodeMeta, "wiki") }

// WikiPermissionDeniedHint returns the stable terminal recovery guidance for
// wiki's 131006 resource-access failure. Keeping it in the classifier lets
// wiki errors retain the same guidance even when surfaced by another shortcut.
func WikiPermissionDeniedHint() string { return wikiPermissionDeniedHint }

func wikiPermissionRecoveryForCode(code int) (recovery.Hint, bool) {
	if code != wikiPermissionDeniedCode {
		return recovery.Hint{}, false
	}
	return recovery.Join("", recovery.Text(wikiPermissionDeniedHint)), true
}
