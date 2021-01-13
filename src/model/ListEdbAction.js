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
import Action from './Action';

/**
 * The ListEdbAction model module.
 * @module model/ListEdbAction
 * @version 1.1.3
 */
class ListEdbAction {
    /**
     * Constructs a new <code>ListEdbAction</code>.
     * @alias module:model/ListEdbAction
     * @extends module:model/Action
     * @implements module:model/Action
     * @param type {String} 
     */
    constructor(type) { 
        Action.initialize(this, type);
        ListEdbAction.initialize(this, type);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj, type) { 
    }

    /**
     * Constructs a <code>ListEdbAction</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:model/ListEdbAction} obj Optional instance to populate.
     * @return {module:model/ListEdbAction} The populated <code>ListEdbAction</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new ListEdbAction();
            Action.constructFromObject(data, obj);
            Action.constructFromObject(data, obj);

            if (data.hasOwnProperty('relname')) {
                obj['relname'] = ApiClient.convertToType(data['relname'], 'String');
            }
        }
        return obj;
    }


}

/**
 * @member {String} relname
 */
ListEdbAction.prototype['relname'] = undefined;


// Implement Action interface:
/**
 * @member {String} type
 * @default ''
 */
Action.prototype['type'] = '';




export default ListEdbAction;

