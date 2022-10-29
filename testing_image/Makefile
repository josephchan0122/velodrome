
replace_ignore:
	if [ -s orig.dockerignore ]; then echo ''; else bash -c 'cp ../.dockerignore orig.dockerignore && cat testing_dockerignore > ../.dockerignore'; fi;

orig_ignore:
	if [ -s orig.dockerignore ]; then bash -c 'cat orig.dockerignore > ../.dockerignore'; fi;
	rm -r orig.dockerignore

build_baseimg:
	$(MAKE) replace_ignore
	bash -c 'cd ../ && docker build -f testing_image/base-testing-velodrome.Dockerfile -t base-velodrome-testing-img .'
	$(MAKE) orig_ignore

launch_tests:
	$(MAKE) replace_ignore
	bash -c 'cd ../ && docker build -f testing_image/testing-launch-velodrome.Dockerfile -t launch-velodrome-testing-img .'
	$(MAKE) orig_ignore
	docker run --name velodrome-test-container -d launch-velodrome-testing-img && sleep 5
	docker exec -it velodrome-test-container /opt/run_tests.sh && \
		docker stop velodrome-test-container && docker rm velodrome-test-container
