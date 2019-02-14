/**
 *    Copyright 2016 floragunn GmbH

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

import Boom from 'boom';
import Joi from 'joi';
const unauthorizedUrlstoExecutives = require('../session/restrictedUrlConfig')

module.exports = function (pluginRoot, server, kbnServer, APP_ROOT, API_ROOT) {

    server.route({
        method: 'GET',
        path: `${API_ROOT}/auth/authinfo`,
        handler: (request, reply) => {
            try {
                let authinfo = server.plugins.searchguard.getSearchGuardBackend().authinfo(request.headers);
                return reply(authinfo);
            } catch(error) {
                if (error.isBoom) {
                    return reply(error);
                }
                throw error;
            }
        }
    });


    server.ext('onPostAuth', async function (request, next) {

        try{
            if (request.auth && request.auth.isAuthenticated) {
                let authinfo = await server.plugins.searchguard.getSearchGuardBackend().authinfo(request.headers);
                const requestPath = request.url.path
                const roles = authinfo ? authinfo.backend_roles : '';
                    unauthorizedUrlstoExecutives.map((element) => {
                        if (roles.includes('admin') === false) {
                            // console.log('roles', roles)
                            // console.log('unauthorizedUrlstoExecutives', unauthorizedUrlstoExecutives)
                            // console.log('requestPath', requestPath)
                            // console.log('element', element)
                            if (requestPath.includes(element)) {
                                if (!requestPath.includes('index.css') && !requestPath.includes('bundles') && !requestPath.includes('assets')) {
                                    const basePath = server.config().get('server.basePath');
                                    // console.log('basePath', basePath)
                                    // return next.redirect(basepath + '/login');
                                    request.auth.session.clear();
                                    // redirect to login somehow?
                                    // return next.continue();
                                }
                            }
                        }
                    });

            }
        }catch(err){
            console.log('err', err)
        }
        return next.continue();
    });

}; //end module
