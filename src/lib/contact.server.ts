import { getRequestHeader } from "@tanstack/react-start/server";
import { z } from "zod";
import { checkRateLimit } from "@/lib/rate-limit.server";

const OWNER_NOTIFICATION_EMAIL = "suriyaprabha30boopalan@gmail.com";

/* =========================
   FORM VALIDATION
========================= */

export const ContactInput = z.object({
  name: z.string().trim().min(2).max(80),

  email: z
    .string()
    .trim()
    .email("Please enter a valid email address.")
    .max(160),

  subject: z.string().trim().min(2).max(140),

  message: z.string().trim().min(10).max(2000),

  // Honeypot field for spam protection
  website: z.string().max(200).optional().default(""),

  // Optional reCAPTCHA token
  captchaToken: z.string().max(4000).optional().default(""),
});

/* =========================
   CAPTCHA VERIFICATION
========================= */

async function verifyCaptcha(token: string, ip: string) {
  const secret = process.env["RECAPTCHA_SECRET_KEY"];

  // If reCAPTCHA is not configured, allow submission.
  if (!secret) {
    return true;
  }

  // If reCAPTCHA is configured but no token is received.
  if (!token) {
    console.error("reCAPTCHA token is missing.");
    return false;
  }

  try {
    const body = new URLSearchParams({
      secret,
      response: token,
    });

    if (ip !== "unknown") {
      body.set("remoteip", ip);
    }

    const response = await fetch(
      "https://www.google.com/recaptcha/api/siteverify",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body,
      },
    );

    const result = (await response.json()) as {
      success?: boolean;
      score?: number;
      action?: string;
    };

    console.log("reCAPTCHA verification result:", result);

    return Boolean(
      result.success &&
        (result.score ?? 0) >= 0.5 &&
        (!result.action || result.action === "contact_form"),
    );
  } catch (error) {
    console.error("reCAPTCHA verification error:", error);
    return false;
  }
}

/* =========================
   SPAM DETECTION
========================= */

function looksLikeSpam(subject: string, message: string) {
  const text = `${subject}\n${message}`;

  const links = (
    text.match(/https?:\/\/|www\.|\[url|\bbit\.ly\b/gi) ?? []
  ).length;

  const spamWords =
    /\b(viagra|casino|crypto giveaway|seo services|loan offer|forex signals)\b/i;

  return (
    links >= 3 ||
    spamWords.test(text) ||
    !/[a-z]/i.test(message)
  );
}

/* =========================
   SEND CONTACT MESSAGE
========================= */

export async function deliverContactMessage(
  data: z.infer<typeof ContactInput>,
) {
  console.log("Contact form submission received:", {
    name: data.name,
    email: data.email,
    subject: data.subject,
  });

  /* ---------- Honeypot + Spam Check ---------- */

  if (
    data.website.trim() ||
    looksLikeSpam(data.subject, data.message)
  ) {
    console.warn("Contact message blocked as spam.");

    return {
      ok: false as const,
      error: "Unable to send your message. Please try again.",
    };
  }

  /* ---------- Get User IP ---------- */

  const ip =
    getRequestHeader("cf-connecting-ip") ??
    getRequestHeader("x-forwarded-for")
      ?.split(",")[0]
      ?.trim() ??
    "unknown";

  console.log("Contact request IP:", ip);

  /* ---------- Verify reCAPTCHA ---------- */

  const captchaValid = await verifyCaptcha(
    data.captchaToken,
    ip,
  );

  if (!captchaValid) {
    return {
      ok: false as const,
      error:
        "We couldn't verify that you're human. Please reload the page and try again.",
    };
  }

  /* ---------- Rate Limiting ---------- */

  const rateLimit = checkRateLimit(
    `contact:${ip}`,
    5,
    10 * 60 * 1000,
  );

  if (!rateLimit.allowed) {
    console.warn("Contact form rate limit reached:", ip);

    return {
      ok: false as const,
      error:
        "Too many messages sent just now. Please try again in a few minutes.",
    };
  }

  /* =========================
     SEND TO FORMSUBMIT
  ========================= */

  try {
    const formSubmitUrl =
      `https://formsubmit.co/ajax/${encodeURIComponent(
        OWNER_NOTIFICATION_EMAIL,
      )}`;

    console.log(
      "Sending contact message to FormSubmit:",
      formSubmitUrl,
    );

    const response = await fetch(formSubmitUrl, {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },

      body: JSON.stringify({
        name: data.name,
        email: data.email,
        subject: data.subject,
        message: data.message,

        _subject: `Portfolio Contact: ${data.subject}`,
        _template: "table",
        _captcha: "false",
      }),
    });

    const responseText = await response.text();

    console.log(
      "FormSubmit status:",
      response.status,
      response.statusText,
    );

    console.log(
      "FormSubmit raw response:",
      responseText,
    );

    let result: {
      success?: boolean | string;
      message?: string;
    } | null = null;

    try {
      result = JSON.parse(responseText);
    } catch (error) {
      console.error(
        "FormSubmit returned invalid JSON:",
        error,
      );
    }

    console.log(
      "FormSubmit parsed response:",
      result,
    );

    const accepted =
      result?.success === true ||
      result?.success === "true";

    if (!response.ok || !accepted) {
      console.error(
        "FormSubmit rejected the contact message:",
        {
          status: response.status,
          statusText: response.statusText,
          result,
          responseText,
        },
      );

      return {
        ok: false as const,
        error:
          result?.message ||
          "Unable to send your message. Please try again.",
      };
    }

    console.log(
      "Contact message successfully sent through FormSubmit.",
    );

    return {
      ok: true as const,
    };
  } catch (error) {
    console.error(
      "CONTACT FORM DELIVERY ERROR:",
      error,
    );

    return {
      ok: false as const,
      error:
        error instanceof Error
          ? `Unable to send message: ${error.message}`
          : "Unable to send your message. Please try again.",
    };
  }
}
