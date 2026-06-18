import { ActivepiecesError, ApplicationEventName, assertNotNullOrUndefined, ErrorCode } from '@activepieces/shared'
import { FastifyPluginAsyncZod } from 'fastify-type-provider-zod'
import { z } from 'zod'
import { securityAccess } from '../../core/security/authorization/fastify-security'
import { applicationEvents } from '../../helper/application-events'
import { networkUtils } from '../../helper/network-utils'
import { system } from '../../helper/system/system'
import { AppSystemProp } from '../../helper/system/system-props'
import { platformUtils } from '../../platform/platform.utils'
import { dgistSsoService } from './dgist-sso.service'

// ai-auth client 등록의 redirect_uri와 정확히 일치해야 한다.
const CALLBACK_PATH = '/api/v1/authn/dgist/callback'

export const dgistSsoController: FastifyPluginAsyncZod = async (app) => {
    // 로그인 시작 — HMAC state 발급 후 ai-auth /authorize로 redirect.
    app.get('/login', LoginRequest, async (req, res) => {
        const state = dgistSsoService(req.log).generateState()
        // redirect_uri는 AP_FRONTEND_URL 고정 — X-Forwarded-Host 스푸핑으로 토큰이 공격자 호스트로 가지 않게.
        const redirectUri = new URL(CALLBACK_PATH, system.getOrThrow(AppSystemProp.FRONTEND_URL)).href
        const authorizeUrl = dgistSsoService(req.log).buildAuthorizeUrl({ state, redirectUri })
        return res.redirect(authorizeUrl)
    })

    // ai-auth form_post 콜백 — state 검증 → JWT 검증·프로비저닝 → 프론트 /authenticate로 세션 전달.
    app.post('/callback', CallbackRequest, async (req, res) => {
        if (!dgistSsoService(req.log).verifyState(req.body.state)) {
            throw new ActivepiecesError({
                code: ErrorCode.INVALID_BEARER_TOKEN,
                params: { message: 'Invalid or expired SSO state' },
            })
        }
        const platformId = await platformUtils.getPlatformIdForRequest(req)
        assertNotNullOrUndefined(platformId, 'Platform Id should not be null')

        const response = await dgistSsoService(req.log).handleCallback({
            accessToken: req.body.access_token,
            platformId,
        })

        const url = new URL('/authenticate', system.getOrThrow(AppSystemProp.FRONTEND_URL))
        url.searchParams.append('response', JSON.stringify(response))

        applicationEvents(req.log).sendUserEvent({
            platformId,
            userId: response.id,
            projectId: response.projectId ?? undefined,
            ip: networkUtils.extractClientRealIp(req, system.get(AppSystemProp.CLIENT_REAL_IP_HEADER)),
        }, {
            action: ApplicationEventName.USER_SIGNED_UP,
            data: { source: 'sso' },
        })

        // T19 완화: 토큰이 쿼리스트링에 담기므로 Referer로의 누출을 차단.
        res.header('Referrer-Policy', 'no-referrer')
        return res.redirect(url.toString())
    })
}

const LoginRequest = {
    config: {
        security: securityAccess.public(),
        rateLimit: { max: 30, timeWindow: '1 minute' },
    },
}

const CallbackRequest = {
    config: {
        security: securityAccess.public(),
        // 익명 자동 프로비저닝 엔드포인트 — brute-force/계정 폭주 방어.
        rateLimit: { max: 30, timeWindow: '1 minute' },
    },
    schema: {
        body: z.object({
            access_token: z.string().min(1).max(8192),
            state: z.string().min(1).max(512),
            expires_in: z.union([z.string(), z.number()]).optional(),
        }),
    },
}
