import { createHmac, randomBytes, timingSafeEqual } from 'crypto'
import { cryptoUtils } from '@activepieces/server-utils'
import {
    ActivepiecesError,
    AuthenticationResponse,
    ErrorCode,
    isNil,
    PlatformRole,
    ProjectType,
    User,
    UserIdentityProvider,
} from '@activepieces/shared'
import { FastifyBaseLogger } from 'fastify'
import jwksClient from 'jwks-rsa'
import { JwtSignAlgorithm, jwtUtils } from '../../helper/jwt-utils'
import { system } from '../../helper/system/system'
import { AppSystemProp } from '../../helper/system/system-props'
import { projectService } from '../../project/project-service'
import { userService } from '../../user/user-service'
import { authenticationUtils } from '../authentication-utils'
import { userIdentityService } from '../user-identity/user-identity-service'

// JWKS 키 로더 — 모듈 1회 초기화 (google-authn-provider 패턴). 키 회전 대비 캐시 + rateLimit.
let keyLoader: ReturnType<typeof jwksClient> | undefined
const getKeyLoader = (): ReturnType<typeof jwksClient> => {
    if (isNil(keyLoader)) {
        keyLoader = jwksClient({
            rateLimit: true,
            cache: true,
            cacheMaxAge: 10 * 60 * 1000,
            jwksUri: system.getOrThrow(AppSystemProp.DGIST_SSO_JWKS_URL),
        })
    }
    return keyLoader
}

// ai-auth JWT에서 신뢰하는 클레임 — 화이트리스트 5개만 (§A.1 default-deny). 나머지 클레임은 전파 금지.
type DgistClaims = {
    sub: string
    email: string
    name: string
    emp_no: string
    role: string
}

export const dgistSsoService = (log: FastifyBaseLogger) => ({
    buildAuthorizeUrl({ state, redirectUri }: BuildAuthorizeUrlParams): string {
        const authorizeUrl = new URL(system.getOrThrow(AppSystemProp.DGIST_SSO_AUTHORIZE_URL))
        authorizeUrl.searchParams.set('client_id', system.getOrThrow(AppSystemProp.DGIST_SSO_CLIENT_ID))
        authorizeUrl.searchParams.set('redirect_uri', redirectUri)
        authorizeUrl.searchParams.set('state', state)
        return authorizeUrl.href
    },

    async handleCallback({ accessToken, platformId }: HandleCallbackParams): Promise<AuthenticationResponse> {
        const claims = await verifyDgistToken(accessToken)
        // fail-close: 필수 클레임이 비면 거부. sub/email은 계정 식별, emp_no/role은 구성원 신분(흐름2에서만 채워짐).
        if (claims.sub === '' || claims.email === '' || claims.emp_no === '' || claims.role === '') {
            throw new ActivepiecesError({
                code: ErrorCode.INVALID_BEARER_TOKEN,
                params: { message: 'DGIST SSO token missing required claims' },
            })
        }
        const user = await provisionUser({ claims, platformId, log })
        // 토큰 발급·프로젝트 선택·검증은 일반 로그인과 동일 경로(getProjectAndToken) 재사용.
        return authenticationUtils(log).getProjectAndToken({
            userId: user.id,
            platformId,
            projectId: null,
        })
    },

    // CSRF state: 쿠키 대신 HMAC 서명 토큰. cross-site form_post에서도 동작(쿠키 sameSite 딜레마 회피),
    // 개발 HTTP/운영 HTTPS 무관. 공격자는 서명을 위조할 수 없고, 5분 만료로 replay 창을 제한한다.
    generateState(): string {
        const nonce = randomBytes(16).toString('hex')
        const exp = String(Date.now() + STATE_TTL_MS)
        return `${nonce}.${exp}.${signStatePayload(`${nonce}.${exp}`)}`
    },

    verifyState(state: string): boolean {
        const parts = state.split('.')
        if (parts.length !== 3) {
            return false
        }
        const [nonce, exp, sig] = parts
        const expected = signStatePayload(`${nonce}.${exp}`)
        const sigBuf = Buffer.from(sig)
        const expectedBuf = Buffer.from(expected)
        if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
            return false
        }
        return Date.now() <= Number(exp)
    },
})

const STATE_TTL_MS = 5 * 60 * 1000

// state 서명 — AP_JWT_SECRET을 HMAC 용도로 재사용(AP access token=JWT와 포맷·검증경로가 달라 혼동 없음).
const signStatePayload = (payload: string): string => {
    return createHmac('sha256', system.getOrThrow(AppSystemProp.JWT_SECRET)).update(payload).digest('hex')
}

const verifyDgistToken = async (jwt: string): Promise<DgistClaims> => {
    const { header } = jwtUtils.decode({ jwt })
    const signingKey = await getKeyLoader().getSigningKey(header.kid)
    const publicKey = signingKey.getPublicKey()
    // RS256 강제 + issuer/audience 검증 (alg 혼동·audience confusion 차단).
    const payload = await jwtUtils.decodeAndVerify<Record<string, unknown>>({
        jwt,
        key: publicKey,
        issuer: system.getOrThrow(AppSystemProp.DGIST_SSO_ISSUER),
        algorithm: JwtSignAlgorithm.RS256,
        audience: system.getOrThrow(AppSystemProp.DGIST_SSO_AUDIENCE),
    })
    // §A.1 화이트리스트 destructure — 5개 필드만 추출하고 나머지 클레임은 버린다.
    return {
        sub: asSafeString(payload.sub),
        email: asSafeString(payload.email),
        name: asSafeString(payload.name),
        emp_no: asSafeString(payload.emp_no),
        role: asSafeString(payload.role),
    }
}

const provisionUser = async ({ claims, platformId, log }: ProvisionUserParams): Promise<User> => {
    const { sub, email, name } = claims
    const cleanEmail = email.trim().toLowerCase()

    // 1) externalId(sub=rel_psn_no)로 기존 사용자 조회 — 가장 안정적인 1차 키 (이메일 변경/재사용 무관).
    const existingUser = await userService(log).getByPlatformAndExternalId({
        platformId,
        externalId: sub,
    })
    if (!isNil(existingUser)) {
        return existingUser
    }

    // 2) 이메일 충돌: 동일 이메일의 비-DGIST(EMAIL 등) 계정이 있으면 자동 링크 금지 → 거부 (계정 탈취 방지).
    const existingIdentity = await userIdentityService(log).getIdentityByEmail(cleanEmail)
    if (!isNil(existingIdentity) && existingIdentity.provider !== UserIdentityProvider.DGIST) {
        throw new ActivepiecesError({
            code: ErrorCode.EXISTING_USER,
            params: { email: cleanEmail, platformId },
        })
    }

    // 3) identity 보장 (없으면 생성). DGIST는 IM이 검증하므로 verified:true, 비밀번호는 임의값(이메일 로그인 비활성).
    const { firstName, lastName } = splitName(name)
    const identity = existingIdentity ?? await userIdentityService(log).create({
        email: cleanEmail,
        password: await cryptoUtils.generateRandomPassword(),
        firstName,
        lastName,
        trackEvents: true,
        newsLetter: false,
        provider: UserIdentityProvider.DGIST,
        verified: true,
    })

    // 4) 사용자 생성 — externalId=sub. platformRole은 MEMBER 리터럴 고정.
    //    ★ role 클레임을 platformRole에 매핑하지 말 것 (조작 시 권한 상승 위험, designer T15).
    let user: User
    try {
        user = await userService(log).create({
            externalId: sub,
            platformId,
            identityId: identity.id,
            platformRole: PlatformRole.MEMBER,
        })
    }
    catch (error) {
        // 동시 콜백 race: (platformId, externalId) unique 충돌이면 먼저 생성된 사용자를 재조회.
        const racedUser = await userService(log).getByPlatformAndExternalId({ platformId, externalId: sub })
        if (!isNil(racedUser)) {
            return racedUser
        }
        throw error
    }

    // 5) 개인 프로젝트 생성 (신규 사용자만, getOrCreateWithProject 로직 미러링).
    await projectService(log).create({
        displayName: `${firstName}'s Project`,
        ownerId: user.id,
        platformId,
        type: ProjectType.PERSONAL,
    })

    return user
}

const splitName = (name: string): { firstName: string, lastName: string } => {
    const trimmed = name.trim()
    if (trimmed.length === 0) {
        return { firstName: 'DGIST', lastName: 'User' }
    }
    // 한글 성명은 분절이 애매하므로 전체를 firstName에 둔다(헤더 인젝션 방지용 길이 제한).
    return { firstName: trimmed.slice(0, 64), lastName: '' }
}

const asSafeString = (value: unknown): string => {
    return typeof value === 'string' ? value : ''
}

type BuildAuthorizeUrlParams = {
    state: string
    redirectUri: string
}

type HandleCallbackParams = {
    accessToken: string
    platformId: string
}

type ProvisionUserParams = {
    claims: DgistClaims
    platformId: string
    log: FastifyBaseLogger
}
