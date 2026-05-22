#pragma once

/*
 * Enroll this agent with the server using a one-time enrollment token.
 * Writes agent_id, agent_secret, and config.json to disk.
 * Returns 1 on success, 0 on failure.
 */
int enroll_agent(const char *server_url, const char *token);
