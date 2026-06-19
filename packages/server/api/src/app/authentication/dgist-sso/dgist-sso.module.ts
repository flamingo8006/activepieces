import { FastifyPluginAsyncZod } from 'fastify-type-provider-zod'
import { system } from '../../helper/system/system'
import { AppSystemProp } from '../../helper/system/system-props'
import { dgistSsoController } from './dgist-sso.controller'

export const dgistSsoModule: FastifyPluginAsyncZod = async (app) => {
    // AP_DGIST_SSO_ENABLED가 false면 라우트 미등록 (기본 비활성).
    if (!system.getBoolean(AppSystemProp.DGIST_SSO_ENABLED)) {
        return
    }
    await app.register(dgistSsoController, { prefix: '/v1/authn/dgist' })
}
