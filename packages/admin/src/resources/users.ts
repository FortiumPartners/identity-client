import type { HttpClient } from '../http.js';
import type {
  User,
  ListUsersParams,
  ListUsersResponse,
  UserResponse,
  CreateUserData,
  UpdateUserData,
  DeleteUserResponse,
} from '../types.js';

/**
 * Sub-client for managing Identity user accounts.
 * Access via `admin.users`.
 *
 * @example
 * ```typescript
 * const { users } = await admin.users.list({ status: 'active' });
 * const user = await admin.users.get('usr_abc123');
 * ```
 */
export class UsersClient {
  constructor(private readonly http: HttpClient) {}

  /**
   * List users with optional filtering and pagination.
   * @param params - Filter and pagination options
   * @returns Users array and pagination metadata
   * @throws {IdentityApiError} On API errors
   */
  async list(params?: ListUsersParams): Promise<ListUsersResponse> {
    return this.http.get<ListUsersResponse>('/api/v1/users', params as Record<string, unknown>);
  }

  /**
   * Auto-paginating async generator that yields all users matching the given filters.
   * Fetches pages of `pageSize` (default 50) and yields individual User objects.
   * @param params - Filter options and optional pageSize
   * @yields {User} Individual user objects
   * @example
   * ```typescript
   * for await (const user of admin.users.listAll({ status: 'active' })) {
   *   console.log(user.email);
   * }
   * ```
   */
  async *listAll(
    params?: Omit<ListUsersParams, 'limit' | 'offset'> & { pageSize?: number },
  ): AsyncIterable<User> {
    const pageSize = params?.pageSize ?? 50;
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const { status, search } = params ?? {};
      const response = await this.list({ limit: pageSize, offset, status, search });
      for (const user of response.users) {
        yield user;
      }
      hasMore = response.pagination.hasMore;
      offset += pageSize;
    }
  }

  /**
   * Get a single user by ID.
   * @param userId - The user's unique identifier
   * @returns The user object
   * @throws {NotFoundError} If the user does not exist
   */
  async get(userId: string): Promise<User> {
    const response = await this.http.get<UserResponse>(`/api/v1/users/${userId}`);
    return response.user;
  }

  /**
   * Create a new user.
   * @param data - User creation data (email, displayName, etc.)
   * @returns The created user object
   * @throws {ConflictError} If a user with the same email already exists
   * @throws {ValidationError} If the input data is invalid
   */
  async create(data: CreateUserData): Promise<User> {
    const response = await this.http.post<UserResponse>('/api/v1/users', data);
    return response.user;
  }

  /**
   * Update user fields (email, displayName, emailVerified).
   * @param userId - The user's unique identifier
   * @param data - Fields to update (only provided fields are changed)
   * @returns The updated user object
   * @throws {NotFoundError} If the user does not exist
   * @throws {ValidationError} If the input data is invalid
   */
  async update(userId: string, data: UpdateUserData): Promise<User> {
    const response = await this.http.patch<UserResponse>(`/api/v1/users/${userId}`, data);
    return response.user;
  }

  /**
   * Update user status (active, suspended, archived).
   * @param userId - The user's unique identifier
   * @param status - New status value
   * @returns The updated user object
   * @throws {NotFoundError} If the user does not exist
   */
  async updateStatus(userId: string, status: 'active' | 'suspended' | 'archived'): Promise<User> {
    const response = await this.http.patch<UserResponse>(`/api/v1/users/${userId}/status`, { status });
    return response.user;
  }

  /**
   * Delete a user permanently.
   * @param userId - The user's unique identifier
   * @throws {NotFoundError} If the user does not exist
   */
  async delete(userId: string): Promise<void> {
    await this.http.delete<DeleteUserResponse>(`/api/v1/users/${userId}`);
  }
}
