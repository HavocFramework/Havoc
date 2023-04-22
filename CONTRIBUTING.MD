# Guide to Contributing

### Pushing Changes to `dev`
- It is preferred that new changes are pushed to a new branch, and then a pull request is made to merge that new branch back into Main/Master
- Steps:
	1. Create a new local branch:
		* `git switch -c <new_branch_name>`
	2. Confirm the new branch was created:
		* `git branch -a`
	3. Confirm the upstream branch you'll be committing to and make a push:
		* `git push -set-upstream origin <new_branch_name>`
