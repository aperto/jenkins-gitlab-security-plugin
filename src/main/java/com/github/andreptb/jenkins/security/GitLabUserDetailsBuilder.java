package com.github.andreptb.jenkins.security;

import com.github.andreptb.jenkins.security.com.github.andreptb.gitlab.GitLabProjectWithPermission;
import com.github.andreptb.jenkins.security.model.GitLabGrantedAuthority;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.lang.StringUtils;
import org.gitlab.api.GitlabAPI;
import org.gitlab.api.models.GitlabAccessLevel;
import org.gitlab.api.models.GitlabPermission;
import org.gitlab.api.models.GitlabProject;
import org.gitlab.api.models.GitlabProjectAccessLevel;
import org.gitlab.api.models.GitlabUser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import hudson.security.Permission;
import jenkins.model.Jenkins;

public class GitLabUserDetailsBuilder {

    public UserDetails buildUserDetails(String gitLabUrl, GitlabUser user, String privateToken) throws IOException {
        Collection<GrantedAuthority> authorities = buildGrantedAuthorities(gitLabUrl, user, privateToken);
        return new User(user.getName(), StringUtils.stripToEmpty(privateToken), !user.isBlocked(), true, true, true, authorities.toArray(new GrantedAuthority[authorities.size()]));
    }

    private Collection<GrantedAuthority> buildGrantedAuthorities(String gitLabUrl, GitlabUser user, String privateToken) throws IOException {
        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        if(user.isAdmin()) {
            authorities.add(new GrantedAuthorityImpl(StringUtils.substringBetween(gitLabUrl, "://", "/") + GitLabGrantedAuthority.GITLAB_ADMIN_SUFFIX));
            return authorities;
        }
        if(StringUtils.isBlank(privateToken)) {
            return authorities;
        }
        GitlabAPI gitlabAPI = GitlabAPI.connect(gitLabUrl, privateToken);
        List<GitlabProject> projects = gitlabAPI.getProjects();
        for (GitlabProject project: projects) {
            authorities.add(buildGrantedAuthority(gitlabAPI, project));
        }
        return authorities;
    }

    private GrantedAuthority buildGrantedAuthority(GitlabAPI gitlabAPI, GitlabProject project) throws IOException {
        GitLabProjectWithPermission projectWithPermission = gitlabAPI.retrieve().to(GitlabProject.URL + "/" + project.getId(), GitLabProjectWithPermission.class);
        GitlabPermission permissions = projectWithPermission.getPermissions();
        GitlabProjectAccessLevel access = permissions.getProjectAccess();
        if(access == null) {
            access = permissions.getProjectGroupAccess();
        }
        return new GitLabGrantedAuthority(projectWithPermission.getNamespace().getName(), projectWithPermission.getName(), createPermissions(access));
    }

    private Collection<Permission> createPermissions(GitlabProjectAccessLevel access) {
        Collection<Permission> permissions = new ArrayList<Permission>();
        permissions.add(Permission.READ);
        permissions.add(Jenkins.READ);
        if(access == null) {
            return permissions;
        }
        GitlabAccessLevel accessLevel = access.getAccessLevel();
        if(accessLevel.accessValue >=  GitlabAccessLevel.Developer.accessValue) {
            permissions.add(Permission.WRITE);
            permissions.add(Permission.CONFIGURE);
        }
        if(accessLevel.accessValue >=  GitlabAccessLevel.Master.accessValue) {
            permissions.add(Jenkins.ADMINISTER);
        }
        return permissions;
    }
}
