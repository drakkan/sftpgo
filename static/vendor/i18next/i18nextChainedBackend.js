(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
  typeof define === 'function' && define.amd ? define(factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, global.i18nextChainedBackend = factory());
})(this, (function () { 'use strict';

  function _classCallCheck(instance, Constructor) {
    if (!(instance instanceof Constructor)) {
      throw new TypeError("Cannot call a class as a function");
    }
  }

  function _typeof(o) {
    "@babel/helpers - typeof";

    return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) {
      return typeof o;
    } : function (o) {
      return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o;
    }, _typeof(o);
  }

  function _toPrimitive(input, hint) {
    if (_typeof(input) !== "object" || input === null) return input;
    var prim = input[Symbol.toPrimitive];
    if (prim !== undefined) {
      var res = prim.call(input, hint || "default");
      if (_typeof(res) !== "object") return res;
      throw new TypeError("@@toPrimitive must return a primitive value.");
    }
    return (hint === "string" ? String : Number)(input);
  }

  function _toPropertyKey(arg) {
    var key = _toPrimitive(arg, "string");
    return _typeof(key) === "symbol" ? key : String(key);
  }

  function _defineProperties(target, props) {
    for (var i = 0; i < props.length; i++) {
      var descriptor = props[i];
      descriptor.enumerable = descriptor.enumerable || false;
      descriptor.configurable = true;
      if ("value" in descriptor) descriptor.writable = true;
      Object.defineProperty(target, _toPropertyKey(descriptor.key), descriptor);
    }
  }
  function _createClass(Constructor, protoProps, staticProps) {
    if (protoProps) _defineProperties(Constructor.prototype, protoProps);
    if (staticProps) _defineProperties(Constructor, staticProps);
    Object.defineProperty(Constructor, "prototype", {
      writable: false
    });
    return Constructor;
  }

  var arr = [];
  var each = arr.forEach;
  var slice = arr.slice;
  function defaults(obj) {
    each.call(slice.call(arguments, 1), function (source) {
      if (source) {
        for (var prop in source) {
          if (obj[prop] === undefined) obj[prop] = source[prop];
        }
      }
    });
    return obj;
  }
  function createClassOnDemand(ClassOrObject) {
    if (!ClassOrObject) return null;
    if (typeof ClassOrObject === 'function') return new ClassOrObject();
    return ClassOrObject;
  }

  function getDefaults() {
    return {
      handleEmptyResourcesAsFailed: true,
      cacheHitMode: 'none'
      // reloadInterval: typeof window !== 'undefined' ? false : 60 * 60 * 1000
      // refreshExpirationTime: 60 * 60 * 1000
    };
  }

  function handleCorrectReadFunction(backend, language, namespace, resolver) {
    var fc = backend.read.bind(backend);
    if (fc.length === 2) {
      // no callback
      try {
        var r = fc(language, namespace);
        if (r && typeof r.then === 'function') {
          // promise
          r.then(function (data) {
            return resolver(null, data);
          })["catch"](resolver);
        } else {
          // sync
          resolver(null, r);
        }
      } catch (err) {
        resolver(err);
      }
      return;
    }

    // normal with callback
    fc(language, namespace, resolver);
  }
  var Backend = /*#__PURE__*/function () {
    function Backend(services) {
      var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
      var i18nextOptions = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
      _classCallCheck(this, Backend);
      this.backends = [];
      this.type = 'backend';
      this.allOptions = i18nextOptions;
      this.init(services, options);
    }
    _createClass(Backend, [{
      key: "init",
      value: function init(services) {
        var _this = this;
        var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
        var i18nextOptions = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
        this.services = services;
        this.options = defaults(options, this.options || {}, getDefaults());
        this.allOptions = i18nextOptions;
        this.options.backends && this.options.backends.forEach(function (b, i) {
          _this.backends[i] = _this.backends[i] || createClassOnDemand(b);
          _this.backends[i].init(services, _this.options.backendOptions && _this.options.backendOptions[i] || {}, i18nextOptions);
        });
        if (this.services && this.options.reloadInterval) {
          setInterval(function () {
            return _this.reload();
          }, this.options.reloadInterval);
        }
      }
    }, {
      key: "read",
      value: function read(language, namespace, callback) {
        var _this2 = this;
        var bLen = this.backends.length;
        var loadPosition = function loadPosition(pos) {
          if (pos >= bLen) return callback(new Error('non of the backend loaded data', true)); // failed pass retry flag
          var isLastBackend = pos === bLen - 1;
          var lengthCheckAmount = _this2.options.handleEmptyResourcesAsFailed && !isLastBackend ? 0 : -1;
          var backend = _this2.backends[pos];
          if (backend.read) {
            handleCorrectReadFunction(backend, language, namespace, function (err, data, savedAt) {
              if (!err && data && Object.keys(data).length > lengthCheckAmount) {
                callback(null, data, pos);
                savePosition(pos - 1, data); // save one in front
                if (backend.save && _this2.options.cacheHitMode && ['refresh', 'refreshAndUpdateStore'].indexOf(_this2.options.cacheHitMode) > -1) {
                  if (savedAt && _this2.options.refreshExpirationTime && savedAt + _this2.options.refreshExpirationTime > Date.now()) return;
                  var nextBackend = _this2.backends[pos + 1];
                  if (nextBackend && nextBackend.read) {
                    handleCorrectReadFunction(nextBackend, language, namespace, function (err, data) {
                      if (err) return;
                      if (!data) return;
                      if (Object.keys(data).length <= lengthCheckAmount) return;
                      savePosition(pos, data);
                      if (_this2.options.cacheHitMode !== 'refreshAndUpdateStore') return;
                      if (_this2.services && _this2.services.resourceStore) {
                        _this2.services.resourceStore.addResourceBundle(language, namespace, data);
                      }
                    });
                  }
                }
              } else {
                loadPosition(pos + 1); // try load from next
              }
            });
          } else {
            loadPosition(pos + 1); // try load from next
          }
        };

        var savePosition = function savePosition(pos, data) {
          if (pos < 0) return;
          var backend = _this2.backends[pos];
          if (backend.save) {
            backend.save(language, namespace, data);
            savePosition(pos - 1, data);
          } else {
            savePosition(pos - 1, data);
          }
        };
        loadPosition(0);
      }
    }, {
      key: "create",
      value: function create(languages, namespace, key, fallbackValue) {
        var clb = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : function () {};
        var opts = arguments.length > 5 && arguments[5] !== undefined ? arguments[5] : {};
        this.backends.forEach(function (b) {
          if (!b.create) return;
          var fc = b.create.bind(b);
          if (fc.length < 6) {
            // no callback
            try {
              var r;
              if (fc.length === 5) {
                // future callback-less api for i18next-locize-backend
                r = fc(languages, namespace, key, fallbackValue, opts);
              } else {
                r = fc(languages, namespace, key, fallbackValue);
              }
              if (r && typeof r.then === 'function') {
                // promise
                r.then(function (data) {
                  return clb(null, data);
                })["catch"](clb);
              } else {
                // sync
                clb(null, r);
              }
            } catch (err) {
              clb(err);
            }
            return;
          }

          // normal with callback
          fc(languages, namespace, key, fallbackValue, clb /* unused callback */, opts);
        });
      }
    }, {
      key: "reload",
      value: function reload() {
        var _this3 = this;
        var _this$services = this.services,
          backendConnector = _this$services.backendConnector,
          languageUtils = _this$services.languageUtils,
          logger = _this$services.logger;
        var currentLanguage = backendConnector.language;
        if (currentLanguage && currentLanguage.toLowerCase() === 'cimode') return; // avoid loading resources for cimode

        var toLoad = [];
        var append = function append(lng) {
          var lngs = languageUtils.toResolveHierarchy(lng);
          lngs.forEach(function (l) {
            if (toLoad.indexOf(l) < 0) toLoad.push(l);
          });
        };
        append(currentLanguage);
        if (this.allOptions.preload) this.allOptions.preload.forEach(function (l) {
          return append(l);
        });
        toLoad.forEach(function (lng) {
          _this3.allOptions.ns.forEach(function (ns) {
            backendConnector.read(lng, ns, 'read', null, null, function (err, data) {
              if (err) logger.warn("loading namespace ".concat(ns, " for language ").concat(lng, " failed"), err);
              if (!err && data) logger.log("loaded namespace ".concat(ns, " for language ").concat(lng), data);
              backendConnector.loaded("".concat(lng, "|").concat(ns), err, data);
            });
          });
        });
      }
    }]);
    return Backend;
  }();
  Backend.type = 'backend';

  return Backend;

}));
