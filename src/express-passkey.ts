import express from 'express'
import {
    generateAuthenticationOptions,
    generateRegistrationOptions, verifyAuthenticationResponse,
    verifyRegistrationResponse
} from "@simplewebauthn/server";
import {AuthenticationResponseJSON, Base64URLString, CredentialDeviceType, PublicKeyCredentialRequestOptionsJSON} from "@simplewebauthn/types"

export class PasskeyServer{
    expressApp: express.Application;
    authFunction: (headers: any, body: any) => boolean;
    successFunction: (userId: string) => string;
    private readonly rpID: string;
    private readonly expectedOrigin: string;
    private challengeStore: Map<string, string>; // nonce, challenge
    private passkeyStore: Map<string, string>;

    /**
     *
     * @param rpID - RelyingParty ID (e.g. URL)
     * @param expectedOrigin - expectedOrigin for browser calls
     * @param app - existing express application to add endpoints to
     * @param authFunction - function will be handed request headers and body to perform user authentication and return result
     * @param successFunction - function is fired at successful user login, receiving the userID of the authenticated user
     */
    constructor(rpID: string,
                expectedOrigin: string,
                app: express.Application,
                authFunction: (headers: any, body: any) => boolean,
                successFunction: (userId: string) => string) {
        this.rpID = rpID;
        this.expectedOrigin = expectedOrigin;
        this.challengeStore = new Map<string, string>();
        this.passkeyStore = new Map<string, string>();
        this.expressApp = app;
        this.authFunction = authFunction;
        this.successFunction = successFunction;
        this.initEndpoints();
    }

    /**
     * Export the internal passkey storage to a JSON string to be backed up
     * @returns string - JSON string needed to later restore the passkey storage
     */
    exportKeys(){
        return(JSON.stringify([...this.passkeyStore]));
    }

    /**
     * Import a previously exported JSON string to be restored
     * @param str - String exported by using exportKeys().
     */
    importKeys(str: string){
        this.passkeyStore = new Map(JSON.parse(str))
    }

    private initEndpoints(){
        this.expressApp.post('/register/start', (req, res) => {
            if (this.authFunction(req.headers, req.body)) {
                this.startRegistration(req).then((registerRes) => {
                    if (registerRes === null)
                        res.status(500).json({ error: 'Error starting passkey registration' });
                    else
                        res.status(200).set('Access-Control-Allow-Origin', this.rpID).json(registerRes);
                });
            }
        });

        this.expressApp.post('/register/finish/:userID', (req, res) => {
            if (this.authFunction(req.headers, req.body)) {
                this.verifyRegistration(req).then((verifyRes) => {
                    if (verifyRes === null)
                        res.status(500).json({ error: 'Error verifying passkey registration' });
                    else
                        res.status(200).send(true);
                });
            }
        })

        this.expressApp.post('/login/start/', (req, res) => {
            this.startLogin().then((loginOptions) => {
                if (loginOptions === undefined) {
                    res.status(400).set('Access-Control-Allow-Origin', this.expectedOrigin).json({ error: 'Error starting passkey verification' });
                }
                else{
                    res.status(200).set('Access-Control-Allow-Origin', this.expectedOrigin).set('no-user-nonce', loginOptions.nonce).json(loginOptions.options);
                }
            })
        });

        this.expressApp.post('/login/finish/', (req, res) => {
            let noUserNonce = req.headers["no-user-nonce"];
            let passkeyJSON = this.passkeyStore.get(req.body.id);
            if (passkeyJSON){
                let passkey = <IPassKey> JSON.parse(passkeyJSON, this.jsonReviver);
                if (passkey && noUserNonce)
                {
                    if (noUserNonce instanceof Array)
                        noUserNonce = noUserNonce[0];
                    this.finishLogin(req, res, passkey, noUserNonce).then(loggedUser => {
                        if (loggedUser === false)
                            res.status(400).set('Access-Control-Allow-Origin', this.expectedOrigin).send();
                        else {
                            let responseBody = this.successFunction(loggedUser)
                            res.status(200).set('Access-Control-Allow-Origin', this.expectedOrigin).send(responseBody);
                        }
                    })
                }
                else {
                    res.status(400).set('Access-Control-Allow-Origin', this.expectedOrigin).json({ error: 'Error processing passkey verification' });
                }
            }
        })
    }

    private async startRegistration(req: express.Request) {
        try {
            let userId:string = req.body.userId;
            let options = await generateRegistrationOptions({
                rpName: 'Fishpond Simulation',
                rpID: this.rpID,
                userID: Uint8Array.from(Buffer.from(userId)),
                userName: req.body.userName,
                userDisplayName: req.body.userDisplayName,
                timeout: 60000,
                excludeCredentials: [],
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    userVerification: 'preferred',
                    residentKey: 'required',
                    requireResidentKey: true
                },
                attestationType: 'none',
                extensions: {},
            });
            this.challengeStore.set(userId, options.challenge);
            return options;
        } catch (error) {
            return null;
        }
    }

    private async verifyRegistration(req: express.Request){
        try {
            let verification = await verifyRegistrationResponse({
                response: req.body,
                expectedChallenge: this.challengeStore.get(req.params.userID) as string,
                expectedOrigin: this.expectedOrigin,
                expectedRPID: this.rpID,
            })
            this.challengeStore.delete(req.params.userID);
            if (verification.verified && verification.registrationInfo) {
                const newPasskey: IPassKey = {
                    user: req.params.userID,
                    webAuthnUserID: req.params.userID,
                    id: verification.registrationInfo.credentialID,
                    publicKey: verification.registrationInfo.credentialPublicKey,
                    counter: verification.registrationInfo.counter,
                    deviceType: verification.registrationInfo.credentialDeviceType,
                    backedUp: verification.registrationInfo.credentialBackedUp,
                    transports: req.body.response.transports
                }
                this.passkeyStore.set(verification.registrationInfo.credentialID, JSON.stringify(newPasskey, this.jsonReplacer))
                return true;
            }
        } catch (error: any) {
            console.error(error);
            return false;
        }
        return false
    }

    private async startLogin(){
        const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
            rpID: this.rpID,
        });
        const nonce = Math.random().toString(36).slice(2, 34);
        this.challengeStore.set(nonce, options.challenge);
        return {nonce: nonce, options: options}
    }

    private async finishLogin(req: express.Request, res:express.Response, passkey: IPassKey, nonce: string){
        let verification;
        let challenge = this.challengeStore.get(nonce) as Base64URLString;
        if (!challenge)
            return false;
        try {
            verification = await verifyAuthenticationResponse({
                response: <AuthenticationResponseJSON> req.body,
                expectedChallenge: challenge,
                expectedOrigin: this.expectedOrigin,
                expectedRPID: this.rpID,
                authenticator: {
                    credentialID: passkey.id,
                    credentialPublicKey: passkey.publicKey,
                    counter: passkey.counter,
                    transports: passkey.transports,
                },
            });
        } catch (error: any) {
            console.error(error);
            return false;
        }
        this.challengeStore.delete(nonce);

        if (verification.verified)
            return passkey.user
        return false;
    }

    private jsonReplacer(key: string, value: any) {
        if (value instanceof Uint8Array) {
            return { type: 'Uint8Array', data: Array.from(value) };
        }
        return value;
    }

    private jsonReviver(key: string, value: any) {
        if (value && value.type === 'Uint8Array') {
            return new Uint8Array(value.data);
        }
        return value;
    }
}

interface IPassKey {
    user: string,
    webAuthnUserID: string,
    id: string,
    publicKey: Uint8Array,
    counter: number,
    deviceType: CredentialDeviceType,
    backedUp: boolean,
    transports: any
}