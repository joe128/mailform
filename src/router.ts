import {NextFunction, Request, Response, Router} from "express";
import formidable, { Fields, Files, File } from 'formidable';
import {TargetManager} from "./services/targetManager";
import {RateLimiter} from "./services/rateLimiter";
import validate from "./services/validate";
import {postBody} from "./models/post";
import {EmailService} from "./services/email";
import {CaptchaService} from "./services/captcha";
import getRedirectUrl from "./util/redirect";
import { FileUtil, JsonBase64File } from "./util/fileUtil";

const router: Router = Router();

/**
 * Check if target exist, validate origin and send CORS headers.
 */
router.use("/:target", async (req: Request, res: Response, next: NextFunction) => {

    let target = TargetManager.targets.get(req.params.target as string);
    if(!target) {
        return res.sendStatus(404);
    }

    // CORS
    res.setHeader("Access-Control-Allow-Origin", target.origin ? target.origin : "*");
    res.setHeader("Access-Control-Allow-Method", "POST");
    res.setHeader("Access-Control-Allow-Headers", "*");

    if(req.method === "OPTIONS") {
        return res.status(200).end();
    }

    // Check origin
    if(target.origin && target.origin !== req.header("origin")) {
        if(target.redirect?.error) return res.redirect(getRedirectUrl(req, target.redirect.error));
        return res.status(403).end();
    }

    // Authentication
    if(target.key) {
        if (!req.headers.authorization) {
            return res.status(401).end();
        }
        let bearer = /Bearer (.+)/.exec(req.headers.authorization);

        if(!bearer || bearer[1] !== target.key) {
            if(target.redirect?.error) return res.redirect(getRedirectUrl(req, target.redirect.error));
            return res.status(401).end();
        }
    }

    return next();

});

router.post("/:target", async (req: Request, res: Response) => {

    // Check rate limit
    const targetParam = req.params.target as string;
    if(!await RateLimiter.consume(targetParam, req.ip ?? "127.0.0.1")) {
        return res.status(429).end();
    }

    let target = TargetManager.targets.get(targetParam);
    if(!target) {
        return res.sendStatus(404);
    }


    // parse form / json-data
    let fieldsMultiple: Fields = {};
    let files: Record<string, File[] | undefined> = {};
    try {
        if (req.is('json') || (req.body && Object.keys(req.body).length > 0)) {
            const bodyFields: Record<string, any> = {};
            const bodyFiles: Record<string, JsonBase64File> = {};

            // expected Json-Format for files: 
            // "attachedFile": { "base64": "...", "filename": "test.pdf", "mimetype": "application/pdf" }
            for (const [key, value] of Object.entries(req.body)) {
                    if (value && typeof value === 'object' && 'base64' in value) {
                        bodyFiles[key] = value as JsonBase64File;
                    } else {
                        bodyFields[key] = value;
                    }
                }

            fieldsMultiple = Object.fromEntries(
                Object.entries(bodyFields).map(([key, value]) => [key, Array.isArray(value) ? value : [value]])
            );

            for (const [key, fileData] of Object.entries(bodyFiles)) {
                try {
                    const mockedFile = await FileUtil.saveBase64AsFormidableFile(
                        fileData.base64,
                        fileData.filename,
                        fileData.mimetype
                    );
                    files[key] = [mockedFile];
                } catch (err) {
                    return res.status(400).json({ error: `Failed to process file for key: ${key}` });
                }
            }

        } else {
            const form = formidable({});
            const [parsedFields, parsedFiles] = await form.parse(req);
            fieldsMultiple = parsedFields;
            files = parsedFiles;
        }
    } catch (parseError) {
        console.error("Parsing failed:", parseError);
        if(target.redirect?.error) return res.redirect(getRedirectUrl(req, target.redirect.error));
        return res.status(500).send("Parse Error"); 
    }

    try {
        const fields = Object.fromEntries(
            Object.entries(fieldsMultiple).map(([key, value]) => [
                key,
                Array.isArray(value) ? value[0] : value
            ])
        );
        const validationResult = validate(fields, postBody);

        // validate fields
        if(validationResult.error) {
            return res.status(422).json(validationResult);
        }

        // Check captcha
        if(target.captcha) {
            const captchaField = fields["g-recaptcha-response"] || fields["h-captcha-response"];
            const userCaptchaResponse = Array.isArray(captchaField) ? captchaField[0] : captchaField;
            
            if (!userCaptchaResponse) {
                if(target.redirect?.error) return res.redirect(getRedirectUrl(req, target.redirect.error));
                return res.status(400).send({ message: "captcha response missing" }).end();
            }
            let verified = await CaptchaService.verifyCaptcha(target.captcha, userCaptchaResponse);

            if(!verified) {
                if(target.redirect?.error) return res.redirect(getRedirectUrl(req, target.redirect.error));
                return res.status(400).send({ message: "captcha verification failed" }).end();
            }
        }

        // extract fields
        const fieldFrom = Array.isArray(fields["from"]) ? fields["from"][0] : fields["from"];
        const fieldFirstName = Array.isArray(fields["firstName"]) ? fields["firstName"][0] : fields["firstName"];
        const fieldLastName = Array.isArray(fields["lastName"]) ? fields["lastName"][0] : fields["lastName"];
        const fieldSubjectPrefix = Array.isArray(fields["subjectPrefix"]) ? fields["subjectPrefix"][0] : fields["subjectPrefix"] ?? "";
        const subject = (target.subjectPrefix ?? "") + fieldSubjectPrefix + (Array.isArray(fields["subject"]) ? fields["subject"][0] : fields["subject"]);
        const fieldBody = Array.isArray(fields["body"]) ? fields["body"][0] : fields["body"];


        // send email
        let from = EmailService.formatFromField(fieldFrom ?? target.from, fieldFirstName, fieldLastName);
        const targetParam = req.params.target as string;
        let sent = await EmailService.sendMail(targetParam, from, subject, fieldBody, files);

        if(sent instanceof Error || !sent) {
            if(target.redirect?.error) return res.redirect(getRedirectUrl(req, target.redirect.error));
            return res.status(500).send({ message: (<Error>sent).message }).end();
        }

        if(target.redirect?.success) {
            return res.redirect(getRedirectUrl(req, target.redirect.success));
        }

        return res.status(200).end();
    } catch (error) {
        console.error("Error in Controller:", error);
        if(target.redirect?.error) return res.redirect(getRedirectUrl(req, target.redirect.error));
        return res.status(500).send({ message: "Internal Server Error" }).end();
    } finally {
        await FileUtil.cleanUpFiles(files as Record<string, File[]>);
    }
});

router.all('/{*splat}', (req: Request, res: Response) => res.status(404).end());

export default router;
