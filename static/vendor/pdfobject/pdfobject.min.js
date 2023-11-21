/**
 *  PDFObject v2.3
 *  https://github.com/pipwerks/PDFObject
 *  @license
 *  Copyright (c) 2008-2023 Philip Hutchison
 *  MIT-style license: http://pipwerks.mit-license.org/
 *  UMD module pattern from https://github.com/umdjs/umd/blob/master/templates/returnExports.js
 */

(function (root, factory) {
    if (typeof define === "function" && define.amd) {
        // AMD. Register as an anonymous module.
        define([], factory);
    } else if (typeof module === "object" && module.exports) {
        // Node. Does not work with strict CommonJS, but
        // only CommonJS-like environments that support module.exports,
        // like Node.
        module.exports = factory();
    } else {
        // Browser globals (root is window)
        root.PDFObject = factory();
  }
}(this, function () {

    "use strict";

    //PDFObject is designed for client-side (browsers), not server-side (node)
    //Will choke on undefined navigator and window vars when run on server
    //Return boolean false and exit function when running server-side

    if(typeof window === "undefined" || window.navigator === undefined || window.navigator.userAgent === undefined){ return false; }

    let pdfobjectversion = "2.3";
    let win = window;
    let nav = win.navigator;
    let ua = nav.userAgent;

    //Fallback validation when navigator.pdfViewerEnabled is not supported
    let isModernBrowser = function (){

        /*
           userAgent sniffing is not the ideal path, but most browsers revoked the ability to check navigator.mimeTypes 
           for security purposes. As of 2023, browsers have begun implementing navigator.pdfViewerEnabled, but older versions
            do not have navigator.pdfViewerEnabled or the ability to check navigator.mimeTypes. We're left with basic browser 
           sniffing and assumptions of PDF support based on browser vendor.
        */

        //Chromium has provided native PDF support since 2011.
        //Most modern browsers use Chromium under the hood: Google Chrome, Microsoft Edge, Opera, Brave, Vivaldi, Arc, and more.
        let isChromium = (win.chrome !== undefined);

        //Safari on macOS has provided native PDF support since 2009. 
        //This code snippet also detects the DuckDuckGo browser, which uses Safari/Webkit under the hood.
        let isSafari = (win.safari !== undefined || (nav.vendor !== undefined && /Apple/.test(nav.vendor) && /Safari/.test(ua)));

        //Firefox has provided PDF support via PDFJS since 2013.
        let isFirefox = (win.Mozilla !== undefined || /irefox/.test(ua));

        return isChromium || isSafari || isFirefox;  

    };

    /*
       Special handling for Internet Explorer 11.
       Check for ActiveX support, then whether "AcroPDF.PDF" or "PDF.PdfCtrl" are valid.
       IE11 uses ActiveX for Adobe Reader and other PDF plugins, but window.ActiveXObject will evaluate to false. ("ActiveXObject" in window) evaluates to true.
       MS Edge does not support ActiveX so this test will evaluate false for MS Edge.
    */
    let validateAX = function (type){
        var ax = null;
        try {
            ax = new ActiveXObject(type);
        } catch (e) {
            //ensure ax remains null when ActiveXObject attempt fails
            ax = null;
        }
        return !!ax; //convert resulting object to boolean
    };

    let hasActiveXPDFPlugin = function (){ return ("ActiveXObject" in win) && (validateAX("AcroPDF.PDF") || validateAX("PDF.PdfCtrl")) };

    let checkSupport = function (){

        //Safari on iPadOS doesn't report as 'mobile' when requesting desktop site, yet still fails to embed PDFs
        let isSafariIOSDesktopMode = (nav.platform !== undefined && nav.platform === "MacIntel" && nav.maxTouchPoints !== undefined && nav.maxTouchPoints > 1);

        let isMobileDevice = (isSafariIOSDesktopMode || /Mobi|Tablet|Android|iPad|iPhone/.test(ua));

        //As of June 2023, no mobile browsers properly support inline PDFs. If mobile, just say no.
        if(isMobileDevice){ return false; }
        
        //Modern browsers began supporting navigator.pdfViewerEnabled in late 2022 and early 2023.
        let supportsPDFVE = (typeof nav.pdfViewerEnabled === "boolean");

        //If browser supports nav.pdfViewerEnabled and is explicitly saying PDFs are NOT supported (e.g. PDFJS disabled by user in Firefox), respect it.
        if(supportsPDFVE && !nav.pdfViewerEnabled){ return false; }

        return (supportsPDFVE && nav.pdfViewerEnabled) || isModernBrowser() || hasActiveXPDFPlugin();

    };

    //Determines whether PDF support is available
    let supportsPDFs = checkSupport();

    //Create a fragment identifier for using PDF Open parameters when embedding PDF
    let buildURLFragmentString = function(pdfParams){

        let string = "";
        let prop;

        if(pdfParams){

            for (prop in pdfParams) {
                if (pdfParams.hasOwnProperty(prop)) {
                    string += encodeURIComponent(prop) + "=" + encodeURIComponent(pdfParams[prop]) + "&";
                }
            }

            //The string will be empty if no PDF Params found
            if(string){

                string = "#" + string;

                //Remove last ampersand
                string = string.slice(0, string.length - 1);

            }

        }

        return string;

    };

    let embedError = function (msg, suppressConsole){
        if(!suppressConsole){
            console.log("[PDFObject] " + msg);
        }
        return false;
    };

    let emptyNodeContents = function (node){
        while(node.firstChild){
            node.removeChild(node.firstChild);
        }
    };

    let getTargetElement = function (targetSelector){

        //Default to body for full-browser PDF
        let targetNode = document.body;

        //If a targetSelector is specified, check to see whether
        //it's passing a selector, jQuery object, or an HTML element

        if(typeof targetSelector === "string"){

            //Is CSS selector
            targetNode = document.querySelector(targetSelector);

        } else if (win.jQuery !== undefined && targetSelector instanceof jQuery && targetSelector.length) {

            //Is jQuery element. Extract HTML node
            targetNode = targetSelector.get(0);

        } else if (targetSelector.nodeType !== undefined && targetSelector.nodeType === 1){

            //Is HTML element
            targetNode = targetSelector;

        }

        return targetNode;

    };

    let generatePDFObjectMarkup = function (embedType, targetNode, url, pdfOpenFragment, width, height, id, title, omitInlineStyles, customAttribute, PDFJS_URL){

        //Ensure target element is empty first
        emptyNodeContents(targetNode);

        let source = url;

        if(embedType === "pdfjs"){ 
            //If PDFJS_URL already contains a ?, assume querystring is in place, and use an ampersand to append PDFJS's file parameter
            let connector = (PDFJS_URL.indexOf("?") !== -1) ? "&" : "?"; 
            source = PDFJS_URL + connector + "file=" + encodeURIComponent(url) + pdfOpenFragment;
        } else {
            source += pdfOpenFragment;
        }

        let el = document.createElement("iframe");
        el.className = "pdfobject";
        el.type = "application/pdf";
        el.title = title;
        el.src = source;
        el.allow = "fullscreen";
        el.frameborder = "0";
        if(id){ el.id = id; }

        if(!omitInlineStyles){

            let style = "border: none;";

            if(targetNode !== document.body){
                //assign width and height to target node
                style += "width: " + width + "; height: " + height + ";";
            } else {
                //this is a full-page embed, use CSS to fill the viewport
                style += "position: absolute; top: 0; right: 0; bottom: 0; left: 0; width: 100%; height: 100%;";
            }

            el.style.cssText = style; 

        }

        //Allow developer to insert custom attribute on iframe element, but ensure it does not conflict with attributes used by PDFObject
        let reservedTokens = ["className", "type", "title", "src", "style", "id", "allow", "frameborder"];
        if(customAttribute && customAttribute.key && reservedTokens.indexOf(customAttribute.key) === -1){
            el.setAttribute(customAttribute.key, (typeof customAttribute.value !== "undefined") ? customAttribute.value : "");
        }

        targetNode.classList.add("pdfobject-container");
        targetNode.appendChild(el);

        return targetNode.getElementsByTagName("iframe")[0];

    };

    let embed = function(url, targetSelector, options){

        //If targetSelector is not defined, convert to boolean
        let selector = targetSelector || false;

        //Ensure options object is not undefined -- enables easier error checking below
        let opt = options || {};

        //Get passed options, or set reasonable defaults
        let id = (typeof opt.id === "string") ? opt.id : "";
        let page = opt.page || false;
        let pdfOpenParams = opt.pdfOpenParams || {};
        let fallbackLink = (typeof opt.fallbackLink === "string" || typeof opt.fallbackLink === "boolean") ? opt.fallbackLink : true;
        let width = opt.width || "100%";
        let height = opt.height || "100%";
        let title = opt.title || "Embedded PDF";
        let forcePDFJS = (typeof opt.forcePDFJS === "boolean") ? opt.forcePDFJS : false;
        let omitInlineStyles = (typeof opt.omitInlineStyles === "boolean") ? opt.omitInlineStyles : false;
        let suppressConsole = (typeof opt.suppressConsole === "boolean") ? opt.suppressConsole : false;
        let PDFJS_URL = opt.PDFJS_URL || false;
        let targetNode = getTargetElement(selector);
        let fallbackHTML = "";
        let pdfOpenFragment = "";
        let customAttribute = opt.customAttribute || {};
        let fallbackHTML_default = "<p>This browser does not support inline PDFs. Please download the PDF to view it: <a href='[url]'>Download PDF</a></p>";

        //Ensure URL is available. If not, exit now.
        if(typeof url !== "string"){ return embedError("URL is not valid", suppressConsole); }

        //If target element is specified but is not valid, exit without doing anything
        if(!targetNode){ return embedError("Target element cannot be determined", suppressConsole); }

        //page option overrides pdfOpenParams, if found
        if(page){ pdfOpenParams.page = page; }

        //Stringify optional Adobe params for opening document (as fragment identifier)
        pdfOpenFragment = buildURLFragmentString(pdfOpenParams);


        // --== Do the dance: Embed attempt #1 ==--

        //If the forcePDFJS option is invoked, skip everything else and embed as directed
        if(forcePDFJS && PDFJS_URL){
            return generatePDFObjectMarkup("pdfjs", targetNode, url, pdfOpenFragment, width, height, id, title, omitInlineStyles, customAttribute, PDFJS_URL);
        }
 
        // --== Embed attempt #2 ==--

        //Embed PDF if support is detected, or if this is a relatively modern browser 
        if(supportsPDFs){
            return generatePDFObjectMarkup("iframe", targetNode, url, pdfOpenFragment, width, height, id, title, omitInlineStyles, customAttribute);
        }
        
        // --== Embed attempt #3 ==--
        
        //If everything else has failed and a PDFJS fallback is provided, try to use it
        if(PDFJS_URL){
            return generatePDFObjectMarkup("pdfjs", targetNode, url, pdfOpenFragment, width, height, id, title, omitInlineStyles, customAttribute, PDFJS_URL);
        }
        
        // --== PDF embed not supported! Use fallback ==-- 

        //Display the fallback link if available
        if(fallbackLink){
            fallbackHTML = (typeof fallbackLink === "string") ? fallbackLink : fallbackHTML_default;
            targetNode.innerHTML = fallbackHTML.replace(/\[url\]/g, url);
        }

        return embedError("This browser does not support embedded PDFs", suppressConsole);

    };

    return {
        embed: function (a,b,c){ return embed(a,b,c); },
        pdfobjectversion: (function () { return pdfobjectversion; })(),
        supportsPDFs: (function (){ return supportsPDFs; })()
    };

}));
