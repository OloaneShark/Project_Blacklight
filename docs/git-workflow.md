# Beginner Git Workflow

Project Blacklight uses a simple branch-and-pull-request workflow so changes can be reviewed and tested before they reach `main`.

## The short version

```text
main
  ↓
create a branch
  ↓
make changes
  ↓
run tests
  ↓
commit
  ↓
push the branch
  ↓
open a pull request
  ↓
review + CI
  ↓
merge into main
```

## Start new work

```bash
git switch main
git pull
git switch -c feature/short-description
```

## Check and save your work

```bash
pytest -q
ruff check blacklight_security tests
git status
git diff
git add .
git commit -m "Describe the change"
```

## Send the branch to GitHub

The first push for a new branch is:

```bash
git push -u origin feature/short-description
```

Later pushes from the same branch can usually be:

```bash
git push
```

## Open a pull request

On GitHub, open a pull request from your feature branch into `main`. The pull request is the review point; pushing a branch does not change `main` by itself.

If CI fails, fix the problem on the same branch, commit, and push again. The existing pull request updates automatically.

## After the pull request is merged

Update your local copy:

```bash
git switch main
git pull
```

Then delete the finished local branch if you no longer need it:

```bash
git branch -d feature/short-description
```

## Merge conflicts

A merge conflict means two branches changed overlapping code and Git cannot safely choose the final version. Resolve the conflicting lines, run the tests again, commit the resolution, and push the branch.

A conflict does not mean the repository is broken; it means a human decision is required before the branches can be combined.
