#!/bin/bash
#
# MANUAL FALLBACK, not used by ClassRepo. Creates student repositories from your own terminal, signed in with your own
# `gh` login (so it has all YOUR permissions and none of the bot's built-in limits), for when ClassRepo itself is unavailable
# or for a local test. It checks its inputs, creates private repositories, invites students with push access and labels the
# repositories `classrepo` so the bot recognises them later. It does not use the encrypted roster or record anything.

# A local command-line script to provision ClassRepo assignments without Cloudflare.
# Requires: GitHub CLI (gh) and jq to be installed on your machine.

ADD_CODESPACES="false"

while getopts "t:a:o:f:ch" opt; do
  case $opt in
    t) TEMPLATE="$OPTARG" ;;
    a) ASSIGNMENT_NAME="$OPTARG" ;;
    o) OWNER="$OPTARG" ;;
    f) FILE="$OPTARG" ;;
    c) ADD_CODESPACES="true" ;;
    h) echo "Usage: $0 -t <template_repo> -a <assignment_name> -o <owner> -f <students.json> [-c (add codespaces badge)]"
       exit 0 ;;
    *) echo "Usage: $0 -t <template_repo> -a <assignment_name> -o <owner> -f <students.json>"
       exit 1 ;;
  esac
done

if [ -z "$TEMPLATE" ] || [ -z "$ASSIGNMENT_NAME" ] || [ -z "$OWNER" ] || [ -z "$FILE" ]; then
    echo "Error: Missing required arguments."
    echo "Usage: $0 -t <template_repo> -a <assignment_name> -o <owner> -f <students.json>"
    exit 1
fi

if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is not installed. Please install it (brew install gh) and run 'gh auth login'."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install it (brew install jq)."
    exit 1
fi

valid() { [[ "$1" =~ $2 ]]; }
valid "$ASSIGNMENT_NAME" '^[A-Za-z0-9._-]{1,60}$' || { echo "Error: the assignment name may only contain letters, numbers, '.', '_' and '-'."; exit 1; }
valid "$TEMPLATE" '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || { echo "Error: the template must look like owner/repo."; exit 1; }
valid "$OWNER" '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$' || { echo "Error: invalid owner."; exit 1; }

if [ ! -f "$FILE" ]; then
    echo "Error: File $FILE not found."
    exit 1
fi

echo "Starting local batch provisioning for $ASSIGNMENT_NAME..."

cat "$FILE" | jq -c '.[]' | while read student; do
    STUDENT_HANDLE=$(echo "$student" | jq -r '.student_handle')
    if ! valid "$STUDENT_HANDLE" '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$'; then echo "Skipping an entry whose student_handle is not a GitHub handle."; continue; fi
    REPO_NAME="${ASSIGNMENT_NAME}-${STUDENT_HANDLE}"

    echo "=========================================="
    echo "Processing $STUDENT_HANDLE -> $REPO_NAME"
    echo "=========================================="
    
    # 1. Create Repository
    echo "Generating repository $REPO_NAME from template $TEMPLATE in $OWNER..."
    gh api --method POST \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      /repos/$TEMPLATE/generate \
      -f owner="$OWNER" \
      -f name="$REPO_NAME" \
      -F private=true \
      -F include_all_branches=false || echo "Warning: Repo generation failed or already exists for $REPO_NAME"

    echo "Waiting for GitHub to initialize repo..."
    sleep 3

    gh api --method PUT /repos/$OWNER/$REPO_NAME/topics -f "names[]=classrepo" >/dev/null || echo "Warning: could not label $REPO_NAME"

    # 2. Invite Student
    echo "Inviting $STUDENT_HANDLE to $REPO_NAME in $OWNER..."
    gh api --method PUT \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      /repos/$OWNER/$REPO_NAME/collaborators/$STUDENT_HANDLE \
      -f permission="push" || echo "Warning: Invite failed for $STUDENT_HANDLE"

    # 3. Optional Codespaces Badge
    if [ "$ADD_CODESPACES" == "true" ]; then
        echo "Adding Codespaces badge to $REPO_NAME..."
        SHA=$(gh api repos/$OWNER/$REPO_NAME/contents/README.md -q .sha 2>/dev/null || echo "")
        BADGE="[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/$OWNER/$REPO_NAME)"
        
        if [ -z "$SHA" ]; then
            CONTENT=$(echo -e "$BADGE" | base64)
            gh api --method PUT repos/$OWNER/$REPO_NAME/contents/README.md \
                -f message="Add Codespaces badge" \
                -f content="$CONTENT" || echo "Warning: Failed to create README for $REPO_NAME"
        else
            EXISTING=$(gh api repos/$OWNER/$REPO_NAME/contents/README.md -q .content 2>/dev/null | tr -d '\n' | base64 -d 2>/dev/null || echo "")
            if ! echo "$EXISTING" | grep -q "codespaces/badge.svg"; then
                CONTENT=$(echo -e "$BADGE\n\n$EXISTING" | base64)
                gh api --method PUT repos/$OWNER/$REPO_NAME/contents/README.md \
                    -f message="Add Codespaces badge" \
                    -f content="$CONTENT" \
                    -f sha="$SHA" || echo "Warning: Failed to update README for $REPO_NAME"
            fi
        fi
    fi

    echo "Finished provisioning for $STUDENT_HANDLE."
    echo ""
done

echo "Batch provisioning complete!"
