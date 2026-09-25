import fs from 'fs';
import path from 'path';
import os from 'os';
import type { File } from 'formidable';

export interface JsonBase64File {
    base64: string;
    filename?: string;
    mimetype?: string;
}

export class FileUtil {
    static async saveBase64AsFormidableFile(
        base64Data: string,
        originalFilename?: string,
        mimetype?: string
    ): Promise<File> {
        if (!base64Data) {
            throw new Error("Base64 data is missing");
        }

        const base64ImageString = base64Data.replace(/^data:.*?;base64,/, "");
        const buffer = Buffer.from(base64ImageString, 'base64');

        const tempDir = os.tmpdir();
        const uniqueFilename = `upload_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
        const filepath = path.join(tempDir, uniqueFilename);

        await fs.promises.writeFile(filepath, buffer);

        return {
            filepath,
            originalFilename: originalFilename || 'unknown',
            newFilename: uniqueFilename,
            mimetype: mimetype || 'application/octet-stream',
            size: buffer.length,
            mtime: new Date(),
            toJSON() { return this; },
            toString(this: { filepath: string }) { 
                return this.filepath; 
            }
        } as unknown as File;
    }

    static async cleanUpFiles(files: Record<string, File[] | undefined>): Promise<void> {
        if (!files || typeof files !== 'object') return;

        const deletePromises: Promise<void>[] = [];

        for (const key in files) {
            const fileArray = files[key];
            if (Array.isArray(fileArray)) {
                for (const file of fileArray) {
                    if (file && file.filepath) {
                        const p = fs.promises.unlink(file.filepath).catch((err) =>
                            console.error(`Error while deleting temporary file ${file.filepath}:`, err)
                        );
                        deletePromises.push(p);
                    }
                }
            }
        }

        await Promise.all(deletePromises);
    }
}
