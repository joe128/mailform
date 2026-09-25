import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import supertest from "supertest";
import router from "./router";
import { TargetManager } from "./services/targetManager";
import { Target } from "./@types/target";
import validate from "./services/validate";
import { RateLimiter } from "./services/rateLimiter";
import { CaptchaService } from "./services/captcha";
import { EmailService } from "./services/email";
import { FileUtil } from './util/fileUtil';

type TargetFromModel = {
    smtp: string;
    origin?: string;
    recipients: string[];
    from?: string;
    subjectPrefix?: string;
    redirect?: {
        success?: string;
        error?: string;
    };
    key?: string;
    rateLimit: {
        timespan: number;
        requests: number;
    };
    captcha?: {
        provider: "recaptcha" | "hcaptcha";
    };
};

vi.mock("./services/targetManager", () => ({
    TargetManager: { targets: { get: vi.fn() } }
}));

vi.mock("./services/rateLimiter", () => ({
    RateLimiter: {
        consume: vi.fn(() => true)
    }
}));

vi.mock("./services/captcha", () => ({
    CaptchaService: {
        verifyCaptcha: vi.fn()
    }
}));

vi.mock("./services/email", () => ({
    EmailService: {
        formatFromField: vi.fn(() => "Sender <from@example.com>"),
        sendMail: vi.fn(() => true)
    }
}));

vi.mock("./services/validate", () => ({
    default: vi.fn(() => ({ error: null }))
}));

vi.mock('./util/fileUtil', { spy: true });

const mockParse = vi.fn();
vi.mock("formidable", () => {
    return {
        default: vi.fn(() => ({
            parse: mockParse
        }))
    };
});

const app = express();
app.use(express.json());
app.use(router);

const createTestTarget = (overrides: Partial<TargetFromModel> = {}): TargetFromModel => ({
    smtp: "smtp://localhost:1025",
    recipients: ["admin@example.com"],
    origin: "",
    from: "default-from@example.com",
    rateLimit: {
        timespan: 60,
        requests: 10
    },
    ...overrides
});

describe("Router Integration Tests", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe("Middleware: /:target Validation & CORS", () => {
        it("should return 404 if target does not exist", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(undefined);

            const response = await supertest(app).post("/unknown-target");
            expect(response.status).toBe(404);
        });

        it("should allow access if target matches model criteria", async () => {
            const mockTarget = createTestTarget({
                origin: "https://mywebsite.com"
            }) as unknown as Target;
            vi.mocked(TargetManager.targets.get).mockReturnValue(mockTarget);

            const response = await supertest(app)
                .post("/my-target")
                .set("Origin", "https://mywebsite.com");

            expect(response.headers["access-control-allow-origin"]).toBe("https://mywebsite.com");
        });

        it("should inject CORS headers and allow request for valid target", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createTestTarget({
                origin: "https://mywebsite.com",
                from: "noreply@example.com"
            }) as unknown as Target);

            const response = await supertest(app)
                .post("/my-target")
                .set("Origin", "https://mywebsite.com");

            expect(response.headers["access-control-allow-origin"]).toBe("https://mywebsite.com");
        });

        it("should return 403 if origin does not match target configuration", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createTestTarget({
                origin: "https://mywebsite.com"
            }) as unknown as Target);

            const response = await supertest(app)
                .post("/my-target")
                .set("Origin", "https://evil-website.com");

            expect(response.status).toBe(403);
        });

        it("should return 401 if target has a key but no auth header is provided", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createTestTarget({
                key: "secret-api-key"
            }) as unknown as Target);

            const response = await supertest(app).post("/my-target");
            expect(response.status).toBe(401);
        });
    });

    describe("POST: /:target Form / Json Processing", () => {
        it("should return 429 if rate limit is exceeded", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createTestTarget({ 
                from: "test@test.de" 
            }) as unknown as Target);
            vi.mocked(RateLimiter.consume).mockResolvedValue(false);

            const response = await supertest(app).post("/my-target");
            expect(response.status).toBe(429);
        });

        it("should return 422 if validation fails after parsing", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createTestTarget() as unknown as Target);
            vi.mocked(RateLimiter.consume).mockResolvedValue(true);

            // Formidable returns parsed fields and files, but we simulate a validation error
            mockParse.mockResolvedValue([
                { from: ["invalid-email"] }, // fieldsMultiple
                {}                           // files
            ]);

            vi.mocked(validate).mockReturnValue({ error: "Email is invalid", problems: [] });

            const response = await supertest(app).post("/my-target");

            expect(response.status).toBe(422);
            expect(response.body).toEqual({ error: "Email is invalid", problems: [] });
        });

        it("should parse data successfully and trigger EmailService", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createTestTarget() as unknown as Target);
            vi.mocked(RateLimiter.consume).mockResolvedValue(true);

            vi.mocked(validate).mockReturnValue({ error: undefined, problems: undefined }); 
            mockParse.mockResolvedValue([
                {
                    from: ["user@example.com"],
                    firstName: ["John"],
                    lastName: ["Doe"],
                    subject: ["Hello World"],
                    body: ["This is a test message."]
                },
                {
                    attachment: [{ filepath: "/tmp/upload_123", originalFilename: "test.pdf" }]
                }
            ]);

            const response = await supertest(app).post("/my-target");

            expect(response.status).toBe(200);

            // Check that EmailService methods were called with expected arguments
            expect(EmailService.formatFromField).toHaveBeenCalledWith("user@example.com", "John", "Doe");
            expect(EmailService.sendMail).toHaveBeenCalledWith(
                "my-target",
                "Sender <from@example.com>",
                "Hello World",
                "This is a test message.",
                expect.any(Object)
            );
        });

        it("should return 500 if Formidable fails to parse the request", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createTestTarget() as unknown as Target);
            vi.mocked(RateLimiter.consume).mockResolvedValue(true);

            mockParse.mockRejectedValue(new Error("Crash while parsing"));

            const response = await supertest(app).post("/my-target");

            expect(response.status).toBe(500);
            expect(response.text).toContain("Parse Error");
        });

        it("should successfully process a valid JSON request with fields and base64 files", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createTestTarget() as unknown as Target);
            vi.mocked(RateLimiter.consume).mockResolvedValue(true);
            
            const mockFileObject = {
                filepath: '/tmp/mock-file.pdf',
                originalFilename: 'test.pdf',
                mimetype: 'application/pdf',
                size: 1234
            };
            vi.spyOn(FileUtil, 'saveBase64AsFormidableFile').mockResolvedValue(mockFileObject as any);
            vi.spyOn(FileUtil, 'cleanUpFiles').mockResolvedValue();

            const validJsonPayload = {
                firstName: "John",
                lastName: "Doe",
                subject: "Test Subject",
                body: "Body-Text",
                myFile: {
                    filename: "test.pdf",
                    mimetype: "application/pdf",
                    base64: "data:application/pdf;base64,JVBERi0xLjQKJ..."
                }
            };

            const response = await supertest(app)
                .post("/my-target")
                .set("Content-Type", "application/json")
                .send(validJsonPayload);

            expect(response.status).toBe(200);
            expect(FileUtil.saveBase64AsFormidableFile).toHaveBeenCalledWith(
                validJsonPayload.myFile.base64,
                validJsonPayload.myFile.filename,
                validJsonPayload.myFile.mimetype
            );
            expect(FileUtil.cleanUpFiles).toHaveBeenCalled();
        });

        it("should return 400 if FileUtil fails to process a base64 file", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createTestTarget() as unknown as Target);
            vi.mocked(RateLimiter.consume).mockResolvedValue(true);

            vi.spyOn(FileUtil, 'saveBase64AsFormidableFile').mockRejectedValue(new Error("Invalid base64 string"));

            const invalidJsonPayload = {
                firstName: "John",
                myFile: {
                    filename: "broken.pdf",
                    mimetype: "application/pdf",
                    base64: "invalid-base64-content"
                }
            };

            const response = await supertest(app)
                .post("/my-target")
                .set("Content-Type", "application/json")
                .send(invalidJsonPayload);

            expect(response.status).toBe(400);
            expect(response.body).toEqual({ error: "Failed to process file for key: myFile" });
        });
    });

    describe("Captcha Verification", () => {
        const createCaptchaTarget = () => ({
            smtp: "smtp://localhost:1025",
            recipients: ["admin@example.com"],
            from: "default-from@example.com",
            origin: "",
            rateLimit: { timespan: 60, requests: 10 },
            captcha: { provider: "recaptcha" as const } 
        });

        it("should return 400 if captcha is required but missing from fields", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createCaptchaTarget() as unknown as Target);
            vi.mocked(validate).mockReturnValue({ error: undefined, problems: undefined });

            // form data without captcha response
            mockParse.mockResolvedValue([
                {
                    from: ["user@example.com"],
                    subject: ["Hello"],
                    body: ["Text"]
                },
                {}
            ]);

            const response = await supertest(app).post("/my-target");

            expect(response.status).toBe(400);
            expect(response.body.message).toBe("captcha response missing");
        });

        it("should return 400 if captcha verification fails", async () => {
            vi.mocked(TargetManager.targets.get).mockReturnValue(createCaptchaTarget() as unknown as Target);
            vi.mocked(validate).mockReturnValue({ error: undefined, problems: undefined });
            
            // simulate that the captcha verification fails
            vi.mocked(CaptchaService.verifyCaptcha).mockResolvedValue(false);

            mockParse.mockResolvedValue([
                {
                    from: ["user@example.com"],
                    subject: ["Hello"],
                    body: ["Text"],
                    "g-recaptcha-response": ["invalid-token-123"]
                },
                {}
            ]);

            const response = await supertest(app).post("/my-target");

            expect(response.status).toBe(400);
            expect(response.body.message).toBe("captcha verification failed");
            
            expect(CaptchaService.verifyCaptcha).toHaveBeenCalledWith(
                { provider: "recaptcha" },
                "invalid-token-123"
            );
        });
    });
});
