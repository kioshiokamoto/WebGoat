/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.WebGoat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Negative tests for {@code POST /service/admin/users/{username}/reset-password}.
 *
 * <p>Unlike {@link AdminControllerTest}, these tests run through the real Spring Security filter
 * chain so that the authentication and authorization controls are exercised as in production.
 */
@SpringBootTest(classes = WebGoat.class)
@TestPropertySource(
    locations = {
      "classpath:/application-webgoat.properties",
      "classpath:/application-webgoat-test.properties"
    })
class AdminResetPasswordNegativeTest {

  private static final String RESET_URL = "/service/admin/users/{username}/reset-password";

  @Autowired private WebApplicationContext wac;
  @MockitoBean private UserService userService;
  @MockitoBean private ClientRegistrationRepository clientRegistrationRepository;

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc = MockMvcBuilders.webAppContextSetup(wac).apply(springSecurity()).build();
  }

  /** Baseline: an admin with a valid username succeeds, so the negative cases are meaningful. */
  @Test
  @WithMockUser(username = "webgoat-admin", authorities = WebGoatUser.ROLE_ADMIN)
  void admin_canResetPassword() throws Exception {
    mockMvc.perform(post(RESET_URL, "webgoat-user")).andExpect(status().isOk());

    verify(userService).resetPassword(eq("webgoat-user"), anyString());
  }

  /** Authorization: an authenticated regular user must not reset someone else's password. */
  @Test
  @WithMockUser(username = "webgoat-user", authorities = WebGoatUser.ROLE_USER)
  void regularUser_isForbidden() throws Exception {
    mockMvc.perform(post(RESET_URL, "webgoat-admin")).andExpect(status().isForbidden());

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  /** Authentication: a request without a session is rejected before reaching the controller. */
  @Test
  void anonymousRequest_isUnauthorized() throws Exception {
    mockMvc
        .perform(post(RESET_URL, "webgoat-user").header("X-Requested-With", "XMLHttpRequest"))
        .andExpect(status().isUnauthorized());

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  /** Input validation: usernames with unexpected characters or length are rejected with 400. */
  @Test
  @WithMockUser(username = "webgoat-admin", authorities = WebGoatUser.ROLE_ADMIN)
  void invalidUsername_isRejected() throws Exception {
    mockMvc.perform(post(RESET_URL, "x' OR '1'='1")).andExpect(status().isBadRequest());
    mockMvc.perform(post(RESET_URL, "<script>")).andExpect(status().isBadRequest());
    mockMvc.perform(post(RESET_URL, "a".repeat(256))).andExpect(status().isBadRequest());

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  /** Error handling: an unknown user yields a plain 404 without leaking the exception message. */
  @Test
  @WithMockUser(username = "webgoat-admin", authorities = WebGoatUser.ROLE_ADMIN)
  void unknownUser_returns404WithoutDetails() throws Exception {
    doThrow(new UsernameNotFoundException("User not found: ghost-user"))
        .when(userService)
        .resetPassword(eq("ghost-user"), anyString());

    mockMvc
        .perform(post(RESET_URL, "ghost-user"))
        .andExpect(status().isNotFound())
        .andExpect(content().string(not(containsString("User not found"))))
        .andExpect(content().string(""));
  }
}
