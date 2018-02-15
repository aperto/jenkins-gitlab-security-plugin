package com.github.andreptb.jenkins.security.com.github.andreptb.gitlab;

import org.gitlab.api.models.GitlabPermission;
import org.gitlab.api.models.GitlabProject;

public class GitLabProjectWithPermission extends GitlabProject {

    private GitlabPermission permissions;

    public GitlabPermission getPermissions() {
        return permissions;
    }

    public void setPermissions(GitlabPermission permissions) {
        this.permissions = permissions;
    }
}
