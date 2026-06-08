import { AuthResponse } from "../../src/types";
import { logger } from "./logger";
import * as Sentry from "@sentry/node";
import { configDotenv } from "dotenv";
import { config } from "../config";
configDotenv();

let warningCount = 0;

export function withAuth<T, U extends any[]>(
  originalFunction: (...args: U) => Promise<T>,
  mockSuccess: T,
) {
  return async function (...args: U): Promise<T> {
    const useDbAuthentication = config.USE_DB_AUTHENTICATION;
    if (!useDbAuthentication) {
      if (config.API_KEY) {
        const req = args[0];
        if (req && typeof req === "object" && "headers" in req) {
          const authHeader =
            req.headers.authorization ??
            (req.headers["sec-websocket-protocol"]
              ? `Bearer ${req.headers["sec-websocket-protocol"]}`
              : null);
          if (!authHeader) {
            return { success: false, error: "Unauthorized: Missing API Key", status: 401 } as any;
          }
          const parts = authHeader.split(" ");
          const token = parts.length > 1 ? parts[1] : parts[0];
          if (token !== config.API_KEY) {
            return { success: false, error: "Unauthorized: Invalid API Key", status: 401 } as any;
          }
        }
      }
      if (warningCount < 5) {
        logger.warn("You're bypassing authentication");
        warningCount++;
      }
      return { success: true, ...(mockSuccess || {}) } as T;
    } else {
      return await originalFunction(...args);
    }
  };
}
