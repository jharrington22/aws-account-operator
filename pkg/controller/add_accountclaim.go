package controller

import (
	"github.com/openshift/aws-account-operator/pkg/controller/accountclaim"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, accountclaim.Add)
}
