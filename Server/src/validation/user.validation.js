import {z} from "zod";

export const registerUserSchema = z.object({
    username: z
    .string()
    .min(3, "Username must be at least 3 characters long")
    .max(20, "Username must be at most 20 characters long")
    .trim(),
    email: z.string().email("Invalid email format").trim(),
    fullName: z.string().min(1, "Full name is required").trim(),
    password: z.string().min(8, "Password must be at least 8 characters long"),
});
