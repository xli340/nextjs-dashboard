import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import { v4 } from 'uuid';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

async function createUser(
  name: string,
  email: string,
  password: string,
): Promise<User | undefined> {
  try {
    // Insert data into the "users" table
    const id = v4();
    const hashedPassword = await bcrypt.hash(password, 10);
    await sql`INSERT INTO users (id, name, email, password)
      VALUES (${id}, ${name}, ${email}, ${hashedPassword})
      ON CONFLICT (id) DO NOTHING;`;

    // Query the newly created user from the database
    const user = await sql<User>`SELECT * FROM users WHERE id = ${id}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to create user:', error);
    throw new Error('Failed to create user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      id: 'login',
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;
          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (passwordsMatch) return user;
        }

        console.log('Invalid credentials');
        return null;
      },
    }),
    Credentials({
      id: 'signup',
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ name: z.string(), email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { name, email, password } = parsedCredentials.data;
          const user = await createUser(name, email, password);
          if (!user) return null;
          return user;
        }

        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});
