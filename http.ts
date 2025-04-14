import { Injectable } from "@angular/core";
import { Utilities } from './utilities';
import { AppError, BusinessError, HttpError } from './customerrorhandler';
import { isNumber } from 'ionic-angular/util/util';

import { LoadingController } from 'ionic-angular';
import { FileLogger } from './filelogger';
import { HTTP, HTTPResponse } from '@ionic-native/http';
import { RequestMethod } from "@angular/http";

export interface HttpRequest {
    url: string;
    method: string;
    body: string;
    headers: any;
    proxyHost: string;
    proxyPort: number;
}

@Injectable()
export class HttpHelper {

    private proxyHost: string;
    private proxyPort: number;

    private showLoader: boolean = true;

    constructor(private http: HTTP, private loadingCtrl: LoadingController,
        private fileLogger: FileLogger) {
        
    }

    public setProxyDetails(pProxyHost: string, pProxyPort: number) {
        this.proxyHost = pProxyHost;
        this.proxyPort = pProxyPort;
    }

    public setProxyAuthDetails(pUsername: string, pPassword: string) {
        this.http.useBasicAuth(pUsername, pPassword);
    }

    public setShowLoader(pShowLoader: boolean) {
        this.showLoader = pShowLoader;
    }

    public downloadFile(pUrl: string, pBody: any, pHeaders: any, pFilePath: string) {
        return new Promise<void>((resolve, reject) => {
            window["cordova"]["plugin"].http.downloadFile(pUrl, pBody, pHeaders, pFilePath, this.proxyHost, this.proxyPort, (pResponse) => {
                resolve();
            }, (pError) => {
                let lError = pError.error;
                try {
                    lError = JSON.parse(lError);
                } catch (e) {

                }
                reject(new HttpError(HttpError.ERROR_GENERAL, pError.status, lError));
            });
        })
    }

    public sendRequest(pUrl: string, pMethod: string, pBody?: any, pHeaders?: {}, pOptions?: {}, pIsBgRequest?: boolean) {
        let lBody: string = (typeof pBody == "string") ? pBody : JSON.stringify(pBody);
        let lBodyJson = pMethod == RequestMethod[RequestMethod.Get] ? "" : lBody;
        let lHttpHeaders = this.parseMapAsHeaders(pHeaders);
        let lOptions = pOptions == null ? {} : pOptions;
        lOptions = { responseType: 'json', ...lOptions };
        const lHttpRequest = {
            url: pUrl,
            method: pMethod,
            body: lBodyJson,
            headers: lHttpHeaders,
            proxyHost: this.proxyHost,
            proxyPort: this.proxyPort
        }
        return this.sendHttpRequest(lHttpRequest, lOptions, pIsBgRequest);
    }

    public sendHttpRequest<T>(pHttpRequest: HttpRequest, pOptions: {}, pIsBgRequest?: boolean): Promise<any> {
        return new Promise<T>((resolve, reject) => {
            let lLoader = null;
            if (!pIsBgRequest && this.showLoader) {
                lLoader = this.showLoading();
                if (!Utilities.isConnected()) {
                    lLoader.dismiss();
                    lLoader.onDidDismiss(() => {
                        reject(new BusinessError(BusinessError.ERROR_GENERAL, "Internet not available"));
                    });
                    return;
                }
            }
            this.fileLogger.debug("sendHttpRequest", pHttpRequest.url);
            this.fileLogger.debug("sendHttpRequest headers", pHttpRequest.headers);
            this.fileLogger.debug("sendHttpRequest body", pHttpRequest.body);
            //console.log("HttpReq:", pHttpRequest);
            //console.log("HttpReq:", pOptions);
            window["cordova"]["plugin"].http.sendRequest(pHttpRequest.url, {
                method: pHttpRequest.method.toLowerCase(),
                data: pHttpRequest.body,
                headers: pHttpRequest.headers,
                timeout: 30,
                proxyHost: pHttpRequest.proxyHost,
                proxyPort: pHttpRequest.proxyPort,
                ...pOptions
            }, (pResponse: HTTPResponse) => {
                if (lLoader != null) {
                    lLoader.dismiss();
                }
                //console.log("HttpReq:", pResponse);
                if (pOptions["responseType"] == 'text') {
                    resolve(<any>pResponse);
                } else {
                    resolve(pResponse.data);
                }
                // this.fileLogger.debug("sendHttpRequest response", pResponse.data);
            }, (pError: HTTPResponse) => {
                this.fileLogger.error("sendHttpRequest", pError.error);
                let lError = pError.error;
                try {
                    lError = JSON.parse(lError);
                } catch (e) {

                }
                if (lLoader == null) {
                    reject(new HttpError(HttpError.ERROR_GENERAL, pError.status, lError));
                } else {
                    lLoader.dismiss();
                    //console.log("HttpReq:", pError);
                    lLoader.onDidDismiss(() => {
                        reject(new HttpError(HttpError.ERROR_GENERAL, pError.status, lError));
                    });
                }
            });
        });
    }

    public parseMapAsHeaders(pMap: {}) {
        let lHttpHeaders = {};
        if (pMap == null || pMap["Content-Type"] == null) {
            lHttpHeaders["Content-Type"] = "application/json";
        } else if (pMap["Content-Type"] == "none") {
            delete pMap["Content-Type"];
        }

        for (let lKey in pMap) {
            let lValue = pMap[lKey];
            if (lValue == null) {
                lValue = "";
            } else if (isNumber(lValue)) {
                lValue = lValue + "";
            }
            lHttpHeaders[lKey] = lValue;
        }
        return lHttpHeaders;
    }

    public showLoading(pMsg?: string) {
        let lLoader = this.loadingCtrl.create({
            content: pMsg
        });
        lLoader.present();
        return lLoader;
    }
}