#!/bin/bash

: ${FIREWALLA_HOME:=/home/pi/firewalla}
: ${FIREWALLA_HIDDEN:=/home/pi/.firewalla}
source ${FIREWALLA_HOME}/platform/platform.sh

if [ -f ~/.fwrc ]; then
  source ~/.fwrc
fi

image=""
image_tag=""

# override image_tag from command line
if [ -n "$1" ]; then
  image_tag=$1
fi

function cleanup_dangling_images() {
    sudo docker images --filter "reference=public.ecr.aws/a0j1s2e9/freeradius*" -f "dangling=true" -q | xargs -r sudo docker rmi
}

# get image tag
function get_image_tag() {
  image_tag=$(redis-cli hget policy:system freeradius_server | jq -r '.options.image_tag // empty')
  if [ -z "$image_tag" ]; then
      image_tag=$(get_release_type)
      if [[ "$image_tag" == "dev" || "$image_tag" == "unknown" ]]; then
        image_tag="dev"
      fi
  fi
}

function get_image() {
  if [[ "$image_tag" == "dev" || "$image_tag" == "test" ]]; then
    image="public.ecr.aws/a0j1s2e9/freeradius-dev:${image_tag}"
  else
    image="public.ecr.aws/a0j1s2e9/freeradius:${image_tag}"
  fi
}

if [ -z "$image_tag" ]; then
  get_image_tag
  get_image
fi

cleanup_dangling_images

echo "checking current image ${image}"
current_image=$(sudo docker images --format "{{.ID}}" --filter "reference=${image}")
if [ -z "$current_image" ]; then
  echo "image ${image} not found"
fi

echo "pulling image ${image}"
sudo docker pull ${image}
if [ $? -ne 0 ]; then
  echo "failed to pull image ${image}"
else
  echo "image ${image} pulled successfully"
fi

new_image=$(sudo docker images --format "{{.ID}}" --filter "reference=${image}")
if [ -z "$new_image" ]; then
  echo "image ${image} not found"
  exit 1
fi

updated=false
if [[ "$current_image" == "$new_image" ]]; then
  echo "image ${image} is up to date"
else 
  updated=true
  echo "image ${image} is updated"
fi

# restart freeradius server if feature is on
feature_on=$(redis-cli hget sys:features freeradius_server)
if [[ "$feature_on" == "1" ]]; then
    if [[ "$updated" == true ]]; then
        sudo systemctl restart docker-compose@freeradius
        # check if freeradius server is running
        if [ $? -ne 0 ]; then
        echo "failed to restart freeradius server"
        else
        echo "freeradius server restarted successfully"
        fi
    fi
else 
    # check if any freeradius container is running then delete
    echo "feature disabled, checking to delete running freeradius container"
    tags=$(sudo docker images --filter "reference=public.ecr.aws/a0j1s2e9/freeradius*" --format "{{.Repository}}:{{.Tag}}")
    for tag in $tags; do
        sudo docker ps -a -q -f "ancestor=$img" | xargs -r sudo docker rm -f
    done
    echo "remaining freeradius containers cleaned up"
fi

# cleanup unexpected containers
sudo docker ps -a --format "{{.Names}}" -f "ancestor=${image}" | grep -v "^freeradius_freeradius_1$" | xargs -r sudo docker rm -f
echo "unexpected containers cleaned up"

# remove other freeradius images except the current image
tags=$(sudo docker images --filter "reference=public.ecr.aws/a0j1s2e9/freeradius*" --format "{{.Repository}}:{{.Tag}}" | grep -v ${image} | grep -v "none")
for tag in $tags; do
  sudo docker rmi $tag
done
echo "image tags ${tags} cleaned up"

# remove all dangling images
cleanup_dangling_images
echo "dangling images removed"

exit 0
