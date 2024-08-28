import sys
from git import Repo

<<<<<<< HEAD
chapters = list(range(1,8))
=======
chapters = list(range(1,12))
>>>>>>> cec4b54 (Add readme, update branch list)
chapters.remove(2)
branches = ['chapter-'+str(i) for i in chapters]

repo = Repo('.')
start_index = branches.index(repo.active_branch.name)
commit = repo.head.object.hexsha

for i in range(start_index + 1, len(branches)):
    repo.git.checkout(branches[i])
    repo.git.cherry_pick(commit)