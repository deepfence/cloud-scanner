PWD=$(shell pwd)
IMAGE_REPOSITORY?=tektite
DF_IMG_TAG?=2.3-ozone

.PHONY: bootstrap steampipe-docker steampipe-docker-push

default: steampipe-docker

bootstrap:
	git submodule update --init --recursive --remote

steampipe-docker:
	docker build -t $(IMAGE_REPOSITORY)/steampipe:$(DF_IMG_TAG) -f Dockerfile.steampipe $(PWD)

steampipe-docker-push:
	docker tag $(IMAGE_REPOSITORY)/steampipe:$(DF_IMG_TAG) $(IMAGE_REPOSITORY)/steampipe:0.23.x
	docker push $(IMAGE_REPOSITORY)/steampipe:0.23.x
