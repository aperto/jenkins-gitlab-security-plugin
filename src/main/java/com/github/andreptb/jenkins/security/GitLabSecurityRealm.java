package com.github.andreptb.jenkins.security;

import com.fasterxml.jackson.core.JsonParseException;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.gitlab.api.GitlabAPI;
import org.gitlab.api.models.GitlabSession;
import org.gitlab.api.models.GitlabUser;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.dao.DataAccessException;

import javax.servlet.ServletException;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import hudson.util.Messages;
import hudson.util.Secret;

public class GitLabSecurityRealm extends AbstractPasswordBasedSecurityRealm {

    private static Logger LOGGER = Logger.getLogger(GitLabSecurityRealm.class.getName());

    private static final String GITLAB_URL_ENV_VAR_KEY = "JENKINS_GITLAB_URL";

    private String gitLabUrl;
    private String apiToken;
    private GitLabUserDetailsBuilder userDetailsBuilder = new GitLabUserDetailsBuilder();

    @DataBoundConstructor
    public GitLabSecurityRealm(String gitLabUrl, String apiToken) {
        this.gitLabUrl = gitLabUrl;
        this.apiToken = apiToken;
    }

    @Override
    protected UserDetails authenticate(String username, String password) throws AuthenticationException {
        try {
            LOGGER.info("Trying to authenticate with username: " + username);
            GitlabSession session = GitlabAPI.connect(this.gitLabUrl, username, password);
            return this.userDetailsBuilder.buildUserDetails(this.gitLabUrl, session, session.getPrivateToken());
        } catch(Exception e) {
            this.LOGGER.log(Level.WARNING, "Authentication request failed for username: " + username, e);
            throw new AuthenticationServiceException("Unable to process authentication for username: " + username, e);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        GitlabAPI api = GitlabAPI.connect(this.gitLabUrl, this.apiToken);
        try {
            GitlabUser[] users = api.retrieve().with("search", username).to(GitlabUser.URL, GitlabUser[].class);
            if(ArrayUtils.isNotEmpty(users)) {
                return this.userDetailsBuilder.buildUserDetails(this.gitLabUrl, users[0], null);
            }
            throw new UsernameNotFoundException("No user found: " + username);
        } catch (IOException e) {
            throw new UsernameNotFoundException("Couldn't find user: " + username, e);
        }
    }

    @Override
    public GroupDetails loadGroupByGroupname(final String groupName) throws UsernameNotFoundException, DataAccessException {
        return new GroupDetails() {
            @Override
            public String getName() {
                return groupName;
            }
        };
    }

    public String getGitLabUrl() {
        return gitLabUrl;
    }

    public String getApiToken() {
        return apiToken;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        public FormValidation doCheckGitLabUrl(@QueryParameter String value) throws IOException, ServletException {
            return FormValidation.validateRequired(value);
        }

        public FormValidation doCheckApiToken(@QueryParameter Secret value, @QueryParameter String gitLabUrl) throws IOException, ServletException {
            String apiToken = value.getPlainText();
            if (StringUtils.isBlank(apiToken)) {
                return FormValidation.error(Messages.FormValidation_ValidateRequired());
            }
            if (StringUtils.isBlank(gitLabUrl)) {
                return FormValidation.error("Please inform GitLab's Server URL");
            }
            try {
                GitlabAPI api = GitlabAPI.connect(gitLabUrl, apiToken).ignoreCertificateErrors(true);
                GitlabUser userFromToken = api.getCurrentSession();
                String username = userFromToken.getName();
                if (!userFromToken.isAdmin()) {
                    return FormValidation.errorWithMarkup("API token owner <b>" + username + "</b> must have administrative privileges");
                }
                return FormValidation.okWithMarkup("Connection established succesfully (API token from owner <b>" + username + "</b>)");
            } catch (JsonParseException e) {
                return FormValidation.error(e, "Unexpected response from server, please confirm if GitLab is responding properly");
            } catch (Exception e) {
                return FormValidation.error(e, "Connection with GitLab failed");
            }
        }

        public static String getDefaultGitLabUrl() {
            return System.getenv(GitLabSecurityRealm.GITLAB_URL_ENV_VAR_KEY);
        }

        /**
         * Gives the name to be displayed by the Jenkins view in the security configuration page.
         *
         * @return the display name
         */
        public String getDisplayName() {
            return "GitLab";
        }
    }
}