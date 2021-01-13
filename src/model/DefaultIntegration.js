/**
 * Delve Client SDK
 * This is a Client SDK for Delve API
 *
 * The version of the OpenAPI document: 1.1.3
 * Contact: support@relational.ai
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 *
 */

import ApiClient from '../ApiClient';
import Integration from './Integration';

/**
 * The DefaultIntegration model module.
 * @module model/DefaultIntegration
 * @version 1.1.3
 */
class DefaultIntegration {
    /**
     * Constructs a new <code>DefaultIntegration</code>.
     * @alias module:model/DefaultIntegration
     * @extends module:model/Integration
     * @implements module:model/Integration
     * @param type {String} 
     */
    constructor(type) { 
        Integration.initialize(this, type);
        DefaultIntegration.initialize(this, type);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj, type) { 
    }

    /**
     * Constructs a <code>DefaultIntegration</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:model/DefaultIntegration} obj Optional instance to populate.
     * @return {module:model/DefaultIntegration} The populated <code>DefaultIntegration</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new DefaultIntegration();
            Integration.constructFromObject(data, obj);
            Integration.constructFromObject(data, obj);

        }
        return obj;
    }


}


// Implement Integration interface:
/**
 * @member {String} type
 * @default ''
 */
Integration.prototype['type'] = '';




export default DefaultIntegration;

