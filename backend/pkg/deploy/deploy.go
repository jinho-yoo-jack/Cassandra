// Package deploy publishes a remediated image and rolls it out to a
// Kubernetes workload with kubectl.
package deploy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/runner"
)

// Deployer pushes images and updates workloads.
type Deployer struct {
	Docker *runner.DockerCLI
	// Registry is prepended to locally built images before pushing, e.g.
	// ghcr.io/acme. Empty means the image is used as is.
	Registry string
	Kubectl  string
}

// Enabled reports whether deploy has anything to do for a target.
func (d *Deployer) Enabled(target *v1alpha1.DeployTarget) bool {
	return d.Registry != "" || target != nil
}

// Deploy pushes image (when a registry is configured) and rolls it out to
// target (when set). It returns the deployed reference and a log.
func (d *Deployer) Deploy(ctx context.Context, image string, target *v1alpha1.DeployTarget) (string, string, error) {
	var log strings.Builder
	ref := image
	if d.Registry != "" {
		ref = strings.TrimSuffix(d.Registry, "/") + "/" + image[strings.LastIndex(image, "/")+1:]
		for _, args := range [][]string{{"tag", image, ref}, {"push", ref}} {
			out, err := d.Docker.Exec(ctx, args...)
			fmt.Fprintf(&log, "$ docker %s\n%s\n", strings.Join(args, " "), out)
			if err != nil {
				return ref, log.String(), err
			}
		}
	}
	if target == nil {
		return ref, log.String(), nil
	}
	base := []string{"--namespace", target.Namespace}
	if target.Context != "" {
		base = append(base, "--context", target.Context)
	}
	steps := [][]string{
		append(append([]string{}, base...), "set", "image", "deployment/"+target.Deployment, target.Container+"="+ref),
		append(append([]string{}, base...), "rollout", "status", "deployment/"+target.Deployment, "--timeout=180s"),
	}
	for _, args := range steps {
		out, err := exec.CommandContext(ctx, d.kubectl(), args...).CombinedOutput()
		fmt.Fprintf(&log, "$ kubectl %s\n%s\n", strings.Join(args, " "), out)
		if err != nil {
			return ref, log.String(), fmt.Errorf("kubectl %s: %w", args[len(base)], err)
		}
	}
	return ref, log.String(), nil
}

func (d *Deployer) kubectl() string {
	if d.Kubectl == "" {
		return "kubectl"
	}
	return d.Kubectl
}
