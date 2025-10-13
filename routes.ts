import bcrypt from "bcrypt";
import type { Express } from "express";
import { createServer, type Server } from "http";
import jwt from "jsonwebtoken";
import { storage } from "./storage";

export async function registerRoutes(app: Express): Promise<Server> {
  const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";
  app.post("/api/signup", async (req, res) => {
    try {
      const { full_name, email, password, confirm_password } = req.body;
      // Basic validation
      if (!full_name || !email || !password || !confirm_password) {
        return res.status(400).json({ error: "All fields are required." });
      }
      if (password !== confirm_password) {
        return res.status(400).json({ error: "Passwords do not match." });
      }
      if (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
        return res.status(400).json({ error: "Password must be at least 8 characters and contain letters and numbers." });
      }
      // Check if user exists
      const existingUser = await storage.getUserByEmail(email);
      if (existingUser) {
        return res.status(409).json({ error: "Email already registered." });
      }
      // Hash password
      const password_hash = await bcrypt.hash(password, 10);
      // Create user
      const user = await storage.createUser({ full_name, email, password_hash });
      return res.status(201).json({ id: user.id, full_name: user.full_name, email: user.email });
    } catch (err) {
      console.error("Signup error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });


  app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }
    const user = await storage.getUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    // Create JWT token
    const token = jwt.sign({ id: user.id, email: user.email, full_name: user.full_name }, JWT_SECRET, { expiresIn: "1h" });
    return res.status(200).json({ token, user: { id: user.id, email: user.email, full_name: user.full_name } });
  });

  const httpServer = createServer(app);
  return httpServer;
}
