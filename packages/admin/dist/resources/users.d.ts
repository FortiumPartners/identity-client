import type { HttpClient } from '../http.js';
import type { User, ListUsersParams, ListUsersResponse, CreateUserData, UpdateUserData } from '../types.js';
export declare class UsersClient {
    private readonly http;
    constructor(http: HttpClient);
    /** List users with optional filtering and pagination */
    list(params?: ListUsersParams): Promise<ListUsersResponse>;
    /**
     * Auto-paginating iterator over all users.
     * Fetches pages of `pageSize` (default 50) and yields individual User objects.
     */
    listAll(params?: Omit<ListUsersParams, 'limit' | 'offset'> & {
        pageSize?: number;
    }): AsyncIterable<User>;
    /** Get a single user by ID. Throws NotFoundError if not found. */
    get(userId: string): Promise<User>;
    /** Create a new user. */
    create(data: CreateUserData): Promise<User>;
    /** Update user fields (email, displayName, emailVerified). */
    update(userId: string, data: UpdateUserData): Promise<User>;
    /** Update user status (active, suspended, archived). */
    updateStatus(userId: string, status: 'active' | 'suspended' | 'archived'): Promise<User>;
    /** Delete a user. Throws NotFoundError if not found. */
    delete(userId: string): Promise<void>;
}
