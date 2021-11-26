package utils

import (
	"os"
	"testing"
)

func TestGetEnvDefaultValue(t *testing.T) {

	DbHost := GetEnv("DB_HOST", "localhost")
	if DbHost != "localhost" {
		t.Error("should be the default value")
	}
}

func TestGetEnvFromSO(t *testing.T) {

	os.Setenv("DB_HOST", "localhost1")

	DbHost := GetEnv("DB_HOST", "localhost")
	if DbHost != "localhost1" {
		t.Error("should be the env variable value")
	}

	os.Unsetenv("DB_HOST")
}
