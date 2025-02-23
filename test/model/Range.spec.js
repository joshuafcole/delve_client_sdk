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

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD.
    define(['expect.js', process.cwd()+'/src/index'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    factory(require('expect.js'), require(process.cwd()+'/src/index'));
  } else {
    // Browser globals (root is window)
    factory(root.expect, root.RaiDbSdk);
  }
}(this, function(expect, RaiDbSdk) {
  'use strict';

  var instance;

  beforeEach(function() {
    instance = new RaiDbSdk.Range();
  });

  var getProperty = function(object, getter, property) {
    // Use getter method if present; otherwise, get the property directly.
    if (typeof object[getter] === 'function')
      return object[getter]();
    else
      return object[property];
  }

  var setProperty = function(object, setter, property, value) {
    // Use setter method if present; otherwise, set the property directly.
    if (typeof object[setter] === 'function')
      object[setter](value);
    else
      object[property] = value;
  }

  describe('Range', function() {
    it('should create an instance of Range', function() {
      // uncomment below and update the code to test Range
      //var instane = new RaiDbSdk.Range();
      //expect(instance).to.be.a(RaiDbSdk.Range);
    });

    it('should have the property area (base name: "area")', function() {
      // uncomment below and update the code to test the property area
      //var instane = new RaiDbSdk.Range();
      //expect(instance).to.be();
    });

    it('should have the property endByte (base name: "end_byte")', function() {
      // uncomment below and update the code to test the property endByte
      //var instane = new RaiDbSdk.Range();
      //expect(instance).to.be();
    });

    it('should have the property input (base name: "input")', function() {
      // uncomment below and update the code to test the property input
      //var instane = new RaiDbSdk.Range();
      //expect(instance).to.be();
    });

    it('should have the property startByte (base name: "start_byte")', function() {
      // uncomment below and update the code to test the property startByte
      //var instane = new RaiDbSdk.Range();
      //expect(instance).to.be();
    });

    it('should have the property type (base name: "type")', function() {
      // uncomment below and update the code to test the property type
      //var instane = new RaiDbSdk.Range();
      //expect(instance).to.be();
    });

  });

}));
