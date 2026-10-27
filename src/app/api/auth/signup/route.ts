import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { db } from "@/lib/db";

const SignupSchema = z.object({
  email: z.string().email("ایمیل معتبر نیست"),
  name: z.string().min(2, "نام حداقل ۲ حرف").max(40).optional().or(z.literal("")),
  password: z.string().min(6, "رمز حداقل ۶ کاراکتر"),
});

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const parsed = SignupSchema.safeParse(body);
    if (!parsed.success) {
      const first = parsed.error.issues[0];
      return NextResponse.json(
        { error: first?.message ?? "ورودی نامعتبر" },
        { status: 400 },
      );
    }

    const email = parsed.data.email.trim().toLowerCase();
    const existing = await db.user.findUnique({ where: { email } });
    if (existing) {
      return NextResponse.json(
        { error: "این ایمیل قبلاً ثبت شده" },
        { status: 409 },
      );
    }

    const passwordHash = await bcrypt.hash(parsed.data.password, 10);
    const user = await db.user.create({
      data: {
        email,
        name: parsed.data.name || null,
        passwordHash,
        settings: { create: {} },
      },
      select: { id: true, email: true, name: true },
    });

    return NextResponse.json({ ok: true, user });
  } catch (err) {
    console.error("[signup] error:", err);
    return NextResponse.json(
      { error: "خطای سرور. دوباره تلاش کن." },
      { status: 500 },
    );
  }
}
