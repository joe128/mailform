export const targetModel = {
    smtp: {
        type: "string",
        presence: { allowEmpty: false },
        url: {
            schemes: ["smtp", "smtps"],
            allowLocal: true
        }
    },
    origin: {
        // sring | string[]
        type: function(value: any) {
            if (value === null || value === undefined) return null;
            
            if (typeof value === "string") return null;
            
            if (Array.isArray(value)) {
                const allStrings = value.every(item => typeof item === "string");
                if (allStrings) {
                    return null; 
                }
                return "must contain only strings";
            }
            
            return "must be a string or an array of strings";
        },
        presence: false
    },
    recipients: {
        type: "array",
        presence: { allowEmpty: false }
    },
    from: {
        type: "string",
        presence: false
    },
    subjectPrefix: {
        type: "string",
        presence: false
    },
    redirect: {
        type: "object",
        presence: false
    },
    "redirect.success": {
        type: "string",
        presence: false
    },
    "redirect.error": {
        type: "string",
        presence: false
    },
    key: {
        type: "string",
        presence: false
    },
    rateLimit: {
        type: "object",
        presence: { allowEmpty: false }
    },
    "rateLimit.timespan": {
        type: "number",
        presence: true
    },
    "rateLimit.requests": {
        type: "number",
        presence: true
    },
    captcha: {
        type: "object",
        presence: false
    },
    "captcha.provider": {
        type: "string",
        inclusion: ["recaptcha", "hcaptcha"]
    }
}