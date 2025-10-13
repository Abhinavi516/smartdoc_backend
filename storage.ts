import { type InsertUser, type User } from "@shared/schema";
import { randomUUID } from "crypto";
import mysql from "mysql2/promise";

// MySQL connection config
// TODO: Replace these values with your actual MySQL credentials
const pool = mysql.createPool({
  host: "localhost",
  user: "root", // <-- your MySQL username
  password: "Srikanth@123", // <-- your MySQL password
  database: "smartdocq_db", // <-- your database name
});

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
}

export class MySQLStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [rows] = await pool.query("SELECT * FROM users WHERE id = ?", [id]);
    return Array.isArray(rows) && rows.length > 0 ? (rows[0] as User) : undefined;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    return Array.isArray(rows) && rows.length > 0 ? (rows[0] as User) : undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    await pool.query(
      "INSERT INTO users (id, full_name, email, password_hash) VALUES (?, ?, ?, ?)",
      [id, insertUser.full_name, insertUser.email, insertUser.password_hash]
    );
    return { id, ...insertUser };
  }
}

export const storage = new MySQLStorage();
