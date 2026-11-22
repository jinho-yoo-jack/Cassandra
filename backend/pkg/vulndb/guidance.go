package vulndb

import (
	"fmt"
	"strings"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

// Guidance returns remediation advice for one component, in Korean, shown on
// graph hover cards and copied into remediation.md.
func Guidance(inv *inventory.Inventory, c *inventory.Component, v *v1alpha1.Vulnerability, fixed string) string {
	var b strings.Builder
	if v.KEV != nil {
		fmt.Fprintf(&b, "[CISA KEV] 실제 악용이 확인된 취약점입니다 (조치 기한 %s). 권고 조치: %s\n", v.KEV.DueDate, v.KEV.RequiredAction)
	}
	if fixed == "" {
		b.WriteString("아직 패치된 버전이 없습니다. 권고문을 확인하고 해당 기능 비활성화, 대체 라이브러리 검토, WAF 규칙 등 완화 조치를 적용하세요.")
		if ref := advisoryURL(v); ref != "" {
			fmt.Fprintf(&b, " 참고: %s", ref)
		}
		return b.String()
	}

	fmt.Fprintf(&b, "%s %s → %s 이상으로 업그레이드하세요. ", c.Name, c.Version, fixed)
	transitive := !c.Direct
	if transitive {
		fmt.Fprintf(&b, "%s 경로로 들어온 전이 의존성입니다. ", pathLabel(inv, c.ID))
	}
	switch c.Ecosystem {
	case inventory.Go:
		if c.Name == "stdlib" {
			fmt.Fprintf(&b, "Go 툴체인을 올리세요: go.mod에 `toolchain go%s`", fixed)
		} else {
			fmt.Fprintf(&b, "`go get %s@%s && go mod tidy`", c.Name, fixed)
		}
	case inventory.NPM:
		if transitive {
			fmt.Fprintf(&b, "상위 패키지를 업그레이드하거나 package.json `overrides`에 `\"%s\": \"%s\"`를 추가하세요.", c.Name, fixed)
		} else {
			fmt.Fprintf(&b, "`npm install %s@%s`", c.Name, fixed)
		}
	case inventory.PyPI:
		fmt.Fprintf(&b, "requirements 또는 pyproject에 `%s>=%s`를 지정하세요.", c.Name, fixed)
	case inventory.Maven:
		if transitive {
			fmt.Fprintf(&b, "`<dependencyManagement>`에 %s %s를 고정하세요.", c.Name, fixed)
		} else {
			fmt.Fprintf(&b, "pom.xml/build.gradle의 %s 버전을 %s로 변경하세요.", c.Name, fixed)
		}
	case inventory.CratesIO:
		fmt.Fprintf(&b, "`cargo update -p %s --precise %s`", c.Name, fixed)
	case inventory.RubyGems:
		fmt.Fprintf(&b, "Gemfile에 `gem '%s', '>= %s'`을 지정하고 `bundle update %s`를 실행하세요.", c.Name, fixed, c.Name)
	case inventory.Packagist:
		fmt.Fprintf(&b, "`composer require %s:^%s`", c.Name, fixed)
	case inventory.Process:
		fmt.Fprintf(&b, "베이스 이미지 태그를 %s 이상 버전으로 바꾸고 이미지를 다시 빌드·배포하세요.", fixed)
	}
	return b.String()
}

func advisoryURL(v *v1alpha1.Vulnerability) string {
	for _, t := range []string{"ADVISORY", "FIX", "WEB"} {
		for _, r := range v.References {
			if r.Type == t {
				return r.URL
			}
		}
	}
	return ""
}

// pathLabel renders the dependency chain from the project to the component.
func pathLabel(inv *inventory.Inventory, componentID string) string {
	ids := inv.PathTo(componentID)
	labels := make([]string, 0, len(ids))
	for _, id := range ids {
		if c := inv.Component(id); c != nil {
			labels = append(labels, c.Name)
			continue
		}
		labels = append(labels, strings.TrimPrefix(id, "project:"))
	}
	return strings.Join(labels, " → ")
}
