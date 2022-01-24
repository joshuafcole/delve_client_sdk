import crypto from "crypto";
const webcrypto = crypto.webcrypto;
import { URL } from "url";
import ConnectionBase from './ConnectionBase.js';
import RelAPIMixin from './RelAPIMixin.js';
import superagent from "superagent";

const Base = RelAPIMixin(ConnectionBase);

/**
 * Class representing a connection to the RAI Cloud.
 *
 * @inherits ConnectionBase
 * @mixes RelAPIMixin
 */

class CloudConnection extends Base {
    config = undefined;
    default_compute = undefined;
    default_service = "transaction";

    _access_token = undefined;

    constructor(config) {
        let oauth2 = {
            get_token(req) { return this.self.get_token(req); },
            self: undefined
        }
        super({
            basePath: `https://${config.host}`,
            authentications: {
                oauth2
            }
        });

        oauth2.self = this;
        this.config = config;
        // this.request_access_token();
    }

    async get_token(req) {
        if(!this._access_token || this.access_token.is_expired()) {
            this.access_token = await this.request_access_token(req);
        }
        return this.access_token?.token;
    }

    async request_access_token(req) {
        let headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Host": new URL(this.config.client_credentials_url).host,
            "User-Agent": "rai-sdk-python/0.6.2", //"rai-sdk-js-fork/0.0.1",
        };
        let body = {
            client_id: this.config.client_id,
            client_secret: this.config.client_secret,
            audience: "https://" + new URL(req.url).host,
            grant_type: "client_credentials",
        };

        let res = await superagent
            .post(this.config.client_credentials_url)
            .set(headers)
            .send(JSON.stringify(body));

        let status_type = res.status / 100 | 0;
        if(status_type !== 2) {
            console.error("Failed to acquire access token", res.status);
            return;
        }
        if(!res.body.access_token) {
            console.error("Failed to acquire access token", res.body);
            return;
        }
        return new AccessToken(res.body.access_token, res.body.expires_in);
    }

    set_compute(compute_name) {
        this.default_compute = compute_name;        
    }

    set_service(service) {
        this.default_service = service;
    }
}

export default CloudConnection;

class AccessToken {
    token = undefined;
    expires_in = undefined;
    created_at = undefined;

    constructor(token, expires_in_seconds) {
        this.token = token;
        this.expires_in = expires_in_seconds * 1000 - 2000;
        this.created_at = Date.now();
    }

    is_expired() {
        return Date.now() - this.created_at >= this.expires_in;
    }
}
