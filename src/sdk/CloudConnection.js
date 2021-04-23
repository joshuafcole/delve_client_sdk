import crypto from "crypto";
const webcrypto = crypto.webcrypto;
import { URL } from "url";
import ConnectionBase from './ConnectionBase.js';
import RelAPIMixin from './RelAPIMixin.js';

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

    constructor(config) {
        let auth = {type: "serverside", sign: undefined};

        super({
            basePath: `https://${config.host}`,
            authentications: {
                serverside: auth
            }
        });

        this.config = config;
        
        // @NOTE: Can't access this prior to calling super. This pattern of passing in the authentications is sad.
        auth.sign = (...args) => this.sign(...args);
    }

    set_compute(compute_name) {
        this.default_compute = compute_name;        
    }

    set_service(service) {
        this.default_service = service;
    }

    async sign(request) {
        let date = new Date();
        let signature_date = get_iso_datetime(date);
        let scope_date = signature_date.slice(0, signature_date.indexOf("T"));

        let scope = [scope_date, this.config.region, this.default_service, "rai01_request"].join("/");

        let req_content = JSON.stringify(request._data);
        let content_hash = crypto.createHash("sha256").update(req_content).digest("hex");

        // @FIXME: This seems not right, but it does appear to be required by the endpoint.
        request.set("host", this.config.host);
      
        request.set("Authorization", null);        
        request.set("x-rai-date", signature_date);

        let all_headers = request._header;

        let canonical_headers = [
            `content-type:${request.get("content-type")}`,
            `host:${request.get("host")}`,
            `x-rai-date:${request.get("x-rai-date")}`,
        ].join("\n");

        let signed_headers = [
            "content-type",
            "host",
            "x-rai-date"
        ].join(";");

        // @FIXME: Why are these all being copied out of request._data (?)
        let body = request._data;
        let required_params = ["dbname", "mode", "readonly"];
        for(let param of required_params) {
            if(!(param in body)) throw new Error("Missing required parameter.");
        }
        
        request.query({
            dbname: body.dbname,
            open_mode: body.mode,
            readonly: body.readonly,
            region: this.config.region,
            compute_name: this.default_compute,
        });
        let raw_query = request.qs;        
        let query = Object.keys(raw_query).sort().map((key) => `${key}=${raw_query[key]}`).join("&");

        let abs_path = new URL(request.url).pathname;

        let canonical_form = [
            request.method,
            encodeURI(abs_path),
            query,
            canonical_headers + "\n",
            signed_headers,
            content_hash
        ].join("\n");

        let canonical_hash = crypto.createHash("sha256").update(canonical_form).digest("hex");
        let string_to_sign = [
            "RAI01-ED25519-SHA256",
            signature_date,
            scope,
            canonical_hash
        ].join("\n");

        // @NOTE: IS this right? Is it extractable?
        let algorithm = { name: "NODE-ED25519", namedCurve: "NODE-ED25519" };
        let seed = Buffer.from(this.config.private_key, "base64");
        let private_key = await webcrypto.subtle.importKey("raw", seed, algorithm, false, ["sign"]);

        let signature_raw = await webcrypto.subtle.sign("NODE-ED25519", private_key, Buffer.from(string_to_sign));
        let signature = Buffer.from(signature_raw).toString("hex");


        let auth_header = `RAI01-ED25519-SHA256 Credential=${this.config.access_key}/${scope}, SignedHeaders=${signed_headers}, Signature=${signature}`;
        request.set("Authorization", auth_header);
    }
}

export default CloudConnection;


function lpad(raw, len, pad = " ") {
    raw = "" + raw;
    if (raw.length < len) return pad.repeat(len - raw.length) + raw;
    else return raw;
}

function get_iso_datetime(date) {
    return [
        lpad(date.getUTCFullYear(), 4, "0"),
        lpad(date.getUTCMonth() + 1, 2, "0"),
        lpad(date.getUTCDate(), 2, "0"),
        "T",
        lpad(date.getUTCHours(), 2, "0"),
        lpad(date.getUTCMinutes(), 2, "0"),
        lpad(date.getUTCSeconds(), 2, "0"),
        "Z"
    ].join("");
}
