package services

import "fmt"

type ToolNameMap struct {
	Forward map[string]string
	Reverse map[string]string
}

func ObfuscateToolNames(names []string) ToolNameMap {
	out := ToolNameMap{Forward: map[string]string{}, Reverse: map[string]string{}}
	for i, name := range names {
		alias := fmt.Sprintf("tool_%d", i+1)
		out.Forward[name] = alias
		out.Reverse[alias] = name
	}
	return out
}
